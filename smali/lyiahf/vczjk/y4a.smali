.class public final Llyiahf/vczjk/y4a;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Ljava/io/Serializable;


# static fields
.field private static final serialVersionUID:J = 0x1L


# instance fields
.field protected final _factory:Llyiahf/vczjk/a4a;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/a4a;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/y4a;->_factory:Llyiahf/vczjk/a4a;

    return-void
.end method

.method public static OooO00o(Llyiahf/vczjk/x4a;Ljava/lang/String;)Ljava/lang/IllegalArgumentException;
    .locals 5

    new-instance v0, Ljava/lang/IllegalArgumentException;

    iget v1, p0, Llyiahf/vczjk/x4a;->OooO0O0:I

    iget-object p0, p0, Llyiahf/vczjk/x4a;->OooO00o:Ljava/lang/String;

    invoke-virtual {p0, v1}, Ljava/lang/String;->substring(I)Ljava/lang/String;

    move-result-object v1

    const-string v2, "Failed to parse type \'"

    const-string v3, "\' (remaining: \'"

    const-string v4, "\'): "

    invoke-static {v2, p0, v3, v1, v4}, Llyiahf/vczjk/q99;->OooO0oo(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object p0

    invoke-virtual {p0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {p0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p0

    invoke-direct {v0, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    return-object v0
.end method


# virtual methods
.method public final OooO0O0(Llyiahf/vczjk/x4a;)Llyiahf/vczjk/x64;
    .locals 6

    invoke-virtual {p1}, Llyiahf/vczjk/x4a;->hasMoreTokens()Z

    move-result v0

    const-string v1, "Unexpected end-of-string"

    if-eqz v0, :cond_6

    invoke-virtual {p1}, Llyiahf/vczjk/x4a;->nextToken()Ljava/lang/String;

    move-result-object v0

    :try_start_0
    iget-object v2, p0, Llyiahf/vczjk/y4a;->_factory:Llyiahf/vczjk/a4a;

    invoke-virtual {v2, v0}, Llyiahf/vczjk/a4a;->OooOOO0(Ljava/lang/String;)Ljava/lang/Class;

    move-result-object v0
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    invoke-virtual {p1}, Llyiahf/vczjk/x4a;->hasMoreTokens()Z

    move-result v2

    const/4 v3, 0x0

    if-eqz v2, :cond_5

    invoke-virtual {p1}, Llyiahf/vczjk/x4a;->nextToken()Ljava/lang/String;

    move-result-object v2

    const-string v4, "<"

    invoke-virtual {v4, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v4

    if-eqz v4, :cond_4

    new-instance v2, Ljava/util/ArrayList;

    invoke-direct {v2}, Ljava/util/ArrayList;-><init>()V

    :goto_0
    invoke-virtual {p1}, Llyiahf/vczjk/x4a;->hasMoreTokens()Z

    move-result v4

    if-eqz v4, :cond_3

    invoke-virtual {p0, p1}, Llyiahf/vczjk/y4a;->OooO0O0(Llyiahf/vczjk/x4a;)Llyiahf/vczjk/x64;

    move-result-object v4

    invoke-virtual {v2, v4}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    invoke-virtual {p1}, Llyiahf/vczjk/x4a;->hasMoreTokens()Z

    move-result v4

    if-eqz v4, :cond_3

    invoke-virtual {p1}, Llyiahf/vczjk/x4a;->nextToken()Ljava/lang/String;

    move-result-object v4

    const-string v5, ">"

    invoke-virtual {v5, v4}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v5

    if-eqz v5, :cond_1

    sget-object p1, Llyiahf/vczjk/i3a;->OooOOO:[Llyiahf/vczjk/x64;

    invoke-virtual {v2}, Ljava/util/ArrayList;->isEmpty()Z

    move-result v1

    if-eqz v1, :cond_0

    goto :goto_1

    :cond_0
    invoke-virtual {v2, p1}, Ljava/util/ArrayList;->toArray([Ljava/lang/Object;)[Ljava/lang/Object;

    move-result-object p1

    check-cast p1, [Llyiahf/vczjk/x64;

    :goto_1
    invoke-static {v0, p1}, Llyiahf/vczjk/i3a;->OooO0Oo(Ljava/lang/Class;[Llyiahf/vczjk/x64;)Llyiahf/vczjk/i3a;

    move-result-object p1

    iget-object v1, p0, Llyiahf/vczjk/y4a;->_factory:Llyiahf/vczjk/a4a;

    invoke-virtual {v1, v3, v0, p1}, Llyiahf/vczjk/a4a;->OooO0OO(Llyiahf/vczjk/uqa;Ljava/lang/Class;Llyiahf/vczjk/i3a;)Llyiahf/vczjk/x64;

    move-result-object p1

    return-object p1

    :cond_1
    const-string v5, ","

    invoke-virtual {v5, v4}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v5

    if-eqz v5, :cond_2

    goto :goto_0

    :cond_2
    new-instance v0, Ljava/lang/StringBuilder;

    const-string v1, "Unexpected token \'"

    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v0, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string v1, "\', expected \',\' or \'>\')"

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    invoke-static {p1, v0}, Llyiahf/vczjk/y4a;->OooO00o(Llyiahf/vczjk/x4a;Ljava/lang/String;)Ljava/lang/IllegalArgumentException;

    move-result-object p1

    throw p1

    :cond_3
    invoke-static {p1, v1}, Llyiahf/vczjk/y4a;->OooO00o(Llyiahf/vczjk/x4a;Ljava/lang/String;)Ljava/lang/IllegalArgumentException;

    move-result-object p1

    throw p1

    :cond_4
    iput-object v2, p1, Llyiahf/vczjk/x4a;->OooO0OO:Ljava/lang/String;

    :cond_5
    iget-object p1, p0, Llyiahf/vczjk/y4a;->_factory:Llyiahf/vczjk/a4a;

    sget-object v1, Llyiahf/vczjk/i3a;->OooOOOO:Llyiahf/vczjk/i3a;

    invoke-virtual {p1, v3, v0, v1}, Llyiahf/vczjk/a4a;->OooO0OO(Llyiahf/vczjk/uqa;Ljava/lang/Class;Llyiahf/vczjk/i3a;)Llyiahf/vczjk/x64;

    move-result-object p1

    return-object p1

    :catch_0
    move-exception v1

    invoke-static {v1}, Llyiahf/vczjk/vy0;->OooOoO(Ljava/lang/Throwable;)V

    new-instance v2, Ljava/lang/StringBuilder;

    const-string v3, "Cannot locate class \'"

    invoke-direct {v2, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string v0, "\', problem: "

    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v1}, Ljava/lang/Throwable;->getMessage()Ljava/lang/String;

    move-result-object v0

    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    invoke-static {p1, v0}, Llyiahf/vczjk/y4a;->OooO00o(Llyiahf/vczjk/x4a;Ljava/lang/String;)Ljava/lang/IllegalArgumentException;

    move-result-object p1

    throw p1

    :cond_6
    invoke-static {p1, v1}, Llyiahf/vczjk/y4a;->OooO00o(Llyiahf/vczjk/x4a;Ljava/lang/String;)Ljava/lang/IllegalArgumentException;

    move-result-object p1

    throw p1
.end method
