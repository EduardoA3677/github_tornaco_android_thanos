.class public final Llyiahf/vczjk/j66;
.super Llyiahf/vczjk/ul1;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/wo1;


# static fields
.field public static final OooOOOO:[Ljava/lang/Object;

.field private static final serialVersionUID:J = 0x1L


# instance fields
.field protected final _elementClass:Ljava/lang/Class;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/lang/Class<",
            "*>;"
        }
    .end annotation
.end field

.field protected _elementDeserializer:Llyiahf/vczjk/e94;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/e94;"
        }
    .end annotation
.end field

.field protected final _elementTypeDeserializer:Llyiahf/vczjk/u3a;

.field protected final _untyped:Z


# direct methods
.method static constructor <clinit>()V
    .locals 1

    const/4 v0, 0x0

    new-array v0, v0, [Ljava/lang/Object;

    sput-object v0, Llyiahf/vczjk/j66;->OooOOOO:[Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/j66;Llyiahf/vczjk/e94;Llyiahf/vczjk/u3a;Llyiahf/vczjk/u46;Ljava/lang/Boolean;)V
    .locals 0

    invoke-direct {p0, p1, p4, p5}, Llyiahf/vczjk/ul1;-><init>(Llyiahf/vczjk/ul1;Llyiahf/vczjk/u46;Ljava/lang/Boolean;)V

    iget-object p4, p1, Llyiahf/vczjk/j66;->_elementClass:Ljava/lang/Class;

    iput-object p4, p0, Llyiahf/vczjk/j66;->_elementClass:Ljava/lang/Class;

    iget-boolean p1, p1, Llyiahf/vczjk/j66;->_untyped:Z

    iput-boolean p1, p0, Llyiahf/vczjk/j66;->_untyped:Z

    iput-object p2, p0, Llyiahf/vczjk/j66;->_elementDeserializer:Llyiahf/vczjk/e94;

    iput-object p3, p0, Llyiahf/vczjk/j66;->_elementTypeDeserializer:Llyiahf/vczjk/u3a;

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/x64;Llyiahf/vczjk/e94;Llyiahf/vczjk/u3a;)V
    .locals 1

    const/4 v0, 0x0

    invoke-direct {p0, p1, v0, v0}, Llyiahf/vczjk/ul1;-><init>(Llyiahf/vczjk/x64;Llyiahf/vczjk/u46;Ljava/lang/Boolean;)V

    invoke-virtual {p1}, Llyiahf/vczjk/x64;->Oooo0oo()Llyiahf/vczjk/x64;

    move-result-object p1

    invoke-virtual {p1}, Llyiahf/vczjk/x64;->OoooO()Ljava/lang/Class;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/j66;->_elementClass:Ljava/lang/Class;

    const-class v0, Ljava/lang/Object;

    if-ne p1, v0, :cond_0

    const/4 p1, 0x1

    goto :goto_0

    :cond_0
    const/4 p1, 0x0

    :goto_0
    iput-boolean p1, p0, Llyiahf/vczjk/j66;->_untyped:Z

    iput-object p2, p0, Llyiahf/vczjk/j66;->_elementDeserializer:Llyiahf/vczjk/e94;

    iput-object p3, p0, Llyiahf/vczjk/j66;->_elementTypeDeserializer:Llyiahf/vczjk/u3a;

    return-void
.end method


# virtual methods
.method public final OooO()Llyiahf/vczjk/o0OoO00O;
    .locals 1

    sget-object v0, Llyiahf/vczjk/o0OoO00O;->OooOOO:Llyiahf/vczjk/o0OoO00O;

    return-object v0
.end method

.method public final OooO0OO(Llyiahf/vczjk/v72;Llyiahf/vczjk/db0;)Llyiahf/vczjk/e94;
    .locals 9

    iget-object v0, p0, Llyiahf/vczjk/j66;->_elementDeserializer:Llyiahf/vczjk/e94;

    iget-object v1, p0, Llyiahf/vczjk/ul1;->_containerType:Llyiahf/vczjk/x64;

    invoke-virtual {v1}, Llyiahf/vczjk/x64;->OoooO()Ljava/lang/Class;

    move-result-object v1

    sget-object v2, Llyiahf/vczjk/n94;->OooOOO0:Llyiahf/vczjk/n94;

    invoke-static {p1, p2, v1, v2}, Llyiahf/vczjk/m49;->OoooO0O(Llyiahf/vczjk/v72;Llyiahf/vczjk/db0;Ljava/lang/Class;Llyiahf/vczjk/n94;)Ljava/lang/Boolean;

    move-result-object v8

    invoke-static {p1, p2, v0}, Llyiahf/vczjk/m49;->OoooO0(Llyiahf/vczjk/v72;Llyiahf/vczjk/db0;Llyiahf/vczjk/e94;)Llyiahf/vczjk/e94;

    move-result-object v0

    iget-object v1, p0, Llyiahf/vczjk/ul1;->_containerType:Llyiahf/vczjk/x64;

    invoke-virtual {v1}, Llyiahf/vczjk/x64;->Oooo0oo()Llyiahf/vczjk/x64;

    move-result-object v1

    if-nez v0, :cond_0

    invoke-virtual {p1, v1, p2}, Llyiahf/vczjk/v72;->o0OoOo0(Llyiahf/vczjk/x64;Llyiahf/vczjk/db0;)Llyiahf/vczjk/e94;

    move-result-object v0

    :goto_0
    move-object v5, v0

    goto :goto_1

    :cond_0
    invoke-virtual {p1, v0, p2, v1}, Llyiahf/vczjk/v72;->o000000O(Llyiahf/vczjk/e94;Llyiahf/vczjk/db0;Llyiahf/vczjk/x64;)Llyiahf/vczjk/e94;

    move-result-object v0

    goto :goto_0

    :goto_1
    iget-object v0, p0, Llyiahf/vczjk/j66;->_elementTypeDeserializer:Llyiahf/vczjk/u3a;

    if-eqz v0, :cond_1

    invoke-virtual {v0, p2}, Llyiahf/vczjk/u3a;->OooO0o(Llyiahf/vczjk/db0;)Llyiahf/vczjk/u3a;

    move-result-object v0

    :cond_1
    move-object v6, v0

    invoke-static {p1, p2, v5}, Llyiahf/vczjk/m49;->OoooO00(Llyiahf/vczjk/v72;Llyiahf/vczjk/db0;Llyiahf/vczjk/e94;)Llyiahf/vczjk/u46;

    move-result-object v7

    iget-object p1, p0, Llyiahf/vczjk/ul1;->_unwrapSingle:Ljava/lang/Boolean;

    if-ne v8, p1, :cond_2

    iget-object p1, p0, Llyiahf/vczjk/ul1;->_nullProvider:Llyiahf/vczjk/u46;

    if-ne v7, p1, :cond_2

    iget-object p1, p0, Llyiahf/vczjk/j66;->_elementDeserializer:Llyiahf/vczjk/e94;

    if-ne v5, p1, :cond_2

    iget-object p1, p0, Llyiahf/vczjk/j66;->_elementTypeDeserializer:Llyiahf/vczjk/u3a;

    if-ne v6, p1, :cond_2

    return-object p0

    :cond_2
    new-instance v3, Llyiahf/vczjk/j66;

    move-object v4, p0

    invoke-direct/range {v3 .. v8}, Llyiahf/vczjk/j66;-><init>(Llyiahf/vczjk/j66;Llyiahf/vczjk/e94;Llyiahf/vczjk/u3a;Llyiahf/vczjk/u46;Ljava/lang/Boolean;)V

    return-object v3
.end method

.method public final OooO0Oo(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)Ljava/lang/Object;
    .locals 7

    invoke-virtual {p2}, Llyiahf/vczjk/eb4;->o0000o0()Z

    move-result v0

    if-nez v0, :cond_0

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/j66;->OoooOoO(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)[Ljava/lang/Object;

    move-result-object p1

    return-object p1

    :cond_0
    invoke-virtual {p1}, Llyiahf/vczjk/v72;->o0000oO()Llyiahf/vczjk/ie;

    move-result-object v0

    invoke-virtual {v0}, Llyiahf/vczjk/ie;->OooOO0o()[Ljava/lang/Object;

    move-result-object v1

    iget-object v2, p0, Llyiahf/vczjk/j66;->_elementTypeDeserializer:Llyiahf/vczjk/u3a;

    const/4 v3, 0x0

    move v4, v3

    :goto_0
    :try_start_0
    invoke-virtual {p2}, Llyiahf/vczjk/eb4;->o0000oOO()Llyiahf/vczjk/gc4;

    move-result-object v5

    sget-object v6, Llyiahf/vczjk/gc4;->OooOOo0:Llyiahf/vczjk/gc4;

    if-eq v5, v6, :cond_5

    sget-object v6, Llyiahf/vczjk/gc4;->OooOoO0:Llyiahf/vczjk/gc4;

    if-ne v5, v6, :cond_2

    iget-boolean v5, p0, Llyiahf/vczjk/ul1;->_skipNullValues:Z

    if-eqz v5, :cond_1

    goto :goto_0

    :cond_1
    iget-object v5, p0, Llyiahf/vczjk/ul1;->_nullProvider:Llyiahf/vczjk/u46;

    invoke-interface {v5, p1}, Llyiahf/vczjk/u46;->OooO0O0(Llyiahf/vczjk/v72;)Ljava/lang/Object;

    move-result-object v5

    goto :goto_1

    :catch_0
    move-exception p1

    goto :goto_3

    :cond_2
    if-nez v2, :cond_3

    iget-object v5, p0, Llyiahf/vczjk/j66;->_elementDeserializer:Llyiahf/vczjk/e94;

    invoke-virtual {v5, p1, p2}, Llyiahf/vczjk/e94;->OooO0Oo(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)Ljava/lang/Object;

    move-result-object v5

    goto :goto_1

    :cond_3
    iget-object v5, p0, Llyiahf/vczjk/j66;->_elementDeserializer:Llyiahf/vczjk/e94;

    invoke-virtual {v5, p2, p1, v2}, Llyiahf/vczjk/e94;->OooO0o(Llyiahf/vczjk/eb4;Llyiahf/vczjk/v72;Llyiahf/vczjk/u3a;)Ljava/lang/Object;

    move-result-object v5

    :goto_1
    array-length v6, v1

    if-lt v4, v6, :cond_4

    invoke-virtual {v0, v1}, Llyiahf/vczjk/ie;->OooO0o0([Ljava/lang/Object;)[Ljava/lang/Object;

    move-result-object v1
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    move v4, v3

    :cond_4
    add-int/lit8 v6, v4, 0x1

    :try_start_1
    aput-object v5, v1, v4
    :try_end_1
    .catch Ljava/lang/Exception; {:try_start_1 .. :try_end_1} :catch_1

    move v4, v6

    goto :goto_0

    :catch_1
    move-exception p1

    move v4, v6

    goto :goto_3

    :cond_5
    iget-boolean p2, p0, Llyiahf/vczjk/j66;->_untyped:Z

    if-eqz p2, :cond_6

    invoke-virtual {v0, v4, v1}, Llyiahf/vczjk/ie;->OooO0oO(I[Ljava/lang/Object;)[Ljava/lang/Object;

    move-result-object p2

    goto :goto_2

    :cond_6
    iget-object p2, p0, Llyiahf/vczjk/j66;->_elementClass:Ljava/lang/Class;

    invoke-virtual {v0, v1, v4, p2}, Llyiahf/vczjk/ie;->OooO0oo([Ljava/lang/Object;ILjava/lang/Class;)[Ljava/lang/Object;

    move-result-object p2

    :goto_2
    invoke-virtual {p1, v0}, Llyiahf/vczjk/v72;->o0000Oo(Llyiahf/vczjk/ie;)V

    return-object p2

    :goto_3
    iget p2, v0, Llyiahf/vczjk/ie;->OooO00o:I

    add-int/2addr p2, v4

    invoke-static {p1, v1, p2}, Llyiahf/vczjk/na4;->OooO0oO(Ljava/lang/Throwable;Ljava/lang/Object;I)Llyiahf/vczjk/na4;

    move-result-object p1

    throw p1
.end method

.method public final OooO0o(Llyiahf/vczjk/eb4;Llyiahf/vczjk/v72;Llyiahf/vczjk/u3a;)Ljava/lang/Object;
    .locals 0

    invoke-virtual {p3, p2, p1}, Llyiahf/vczjk/u3a;->OooO0OO(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, [Ljava/lang/Object;

    return-object p1
.end method

.method public final OooO0o0(Llyiahf/vczjk/eb4;Llyiahf/vczjk/v72;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 6

    check-cast p3, [Ljava/lang/Object;

    invoke-virtual {p1}, Llyiahf/vczjk/eb4;->o0000o0()Z

    move-result v0

    const/4 v1, 0x0

    if-nez v0, :cond_1

    invoke-virtual {p0, p2, p1}, Llyiahf/vczjk/j66;->OoooOoO(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)[Ljava/lang/Object;

    move-result-object p1

    if-nez p1, :cond_0

    return-object p3

    :cond_0
    array-length p2, p3

    array-length v0, p1

    add-int/2addr v0, p2

    new-array v0, v0, [Ljava/lang/Object;

    invoke-static {p3, v1, v0, v1, p2}, Ljava/lang/System;->arraycopy(Ljava/lang/Object;ILjava/lang/Object;II)V

    array-length p3, p1

    invoke-static {p1, v1, v0, p2, p3}, Ljava/lang/System;->arraycopy(Ljava/lang/Object;ILjava/lang/Object;II)V

    return-object v0

    :cond_1
    invoke-virtual {p2}, Llyiahf/vczjk/v72;->o0000oO()Llyiahf/vczjk/ie;

    move-result-object v0

    array-length v2, p3

    invoke-virtual {v0, v2, p3}, Llyiahf/vczjk/ie;->OooOOO0(I[Ljava/lang/Object;)[Ljava/lang/Object;

    move-result-object p3

    iget-object v3, p0, Llyiahf/vczjk/j66;->_elementTypeDeserializer:Llyiahf/vczjk/u3a;

    :goto_0
    :try_start_0
    invoke-virtual {p1}, Llyiahf/vczjk/eb4;->o0000oOO()Llyiahf/vczjk/gc4;

    move-result-object v4

    sget-object v5, Llyiahf/vczjk/gc4;->OooOOo0:Llyiahf/vczjk/gc4;

    if-eq v4, v5, :cond_6

    sget-object v5, Llyiahf/vczjk/gc4;->OooOoO0:Llyiahf/vczjk/gc4;

    if-ne v4, v5, :cond_3

    iget-boolean v4, p0, Llyiahf/vczjk/ul1;->_skipNullValues:Z

    if-eqz v4, :cond_2

    goto :goto_0

    :cond_2
    iget-object v4, p0, Llyiahf/vczjk/ul1;->_nullProvider:Llyiahf/vczjk/u46;

    invoke-interface {v4, p2}, Llyiahf/vczjk/u46;->OooO0O0(Llyiahf/vczjk/v72;)Ljava/lang/Object;

    move-result-object v4

    goto :goto_1

    :catch_0
    move-exception p1

    goto :goto_3

    :cond_3
    if-nez v3, :cond_4

    iget-object v4, p0, Llyiahf/vczjk/j66;->_elementDeserializer:Llyiahf/vczjk/e94;

    invoke-virtual {v4, p2, p1}, Llyiahf/vczjk/e94;->OooO0Oo(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)Ljava/lang/Object;

    move-result-object v4

    goto :goto_1

    :cond_4
    iget-object v4, p0, Llyiahf/vczjk/j66;->_elementDeserializer:Llyiahf/vczjk/e94;

    invoke-virtual {v4, p1, p2, v3}, Llyiahf/vczjk/e94;->OooO0o(Llyiahf/vczjk/eb4;Llyiahf/vczjk/v72;Llyiahf/vczjk/u3a;)Ljava/lang/Object;

    move-result-object v4

    :goto_1
    array-length v5, p3

    if-lt v2, v5, :cond_5

    invoke-virtual {v0, p3}, Llyiahf/vczjk/ie;->OooO0o0([Ljava/lang/Object;)[Ljava/lang/Object;

    move-result-object p3
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    move v2, v1

    :cond_5
    add-int/lit8 v5, v2, 0x1

    :try_start_1
    aput-object v4, p3, v2
    :try_end_1
    .catch Ljava/lang/Exception; {:try_start_1 .. :try_end_1} :catch_1

    move v2, v5

    goto :goto_0

    :catch_1
    move-exception p1

    move v2, v5

    goto :goto_3

    :cond_6
    iget-boolean p1, p0, Llyiahf/vczjk/j66;->_untyped:Z

    if-eqz p1, :cond_7

    invoke-virtual {v0, v2, p3}, Llyiahf/vczjk/ie;->OooO0oO(I[Ljava/lang/Object;)[Ljava/lang/Object;

    move-result-object p1

    goto :goto_2

    :cond_7
    iget-object p1, p0, Llyiahf/vczjk/j66;->_elementClass:Ljava/lang/Class;

    invoke-virtual {v0, p3, v2, p1}, Llyiahf/vczjk/ie;->OooO0oo([Ljava/lang/Object;ILjava/lang/Class;)[Ljava/lang/Object;

    move-result-object p1

    :goto_2
    invoke-virtual {p2, v0}, Llyiahf/vczjk/v72;->o0000Oo(Llyiahf/vczjk/ie;)V

    return-object p1

    :goto_3
    iget p2, v0, Llyiahf/vczjk/ie;->OooO00o:I

    add-int/2addr p2, v2

    invoke-static {p1, p3, p2}, Llyiahf/vczjk/na4;->OooO0oO(Ljava/lang/Throwable;Ljava/lang/Object;I)Llyiahf/vczjk/na4;

    move-result-object p1

    throw p1
.end method

.method public final OooOO0(Llyiahf/vczjk/v72;)Ljava/lang/Object;
    .locals 0

    sget-object p1, Llyiahf/vczjk/j66;->OooOOOO:[Ljava/lang/Object;

    return-object p1
.end method

.method public final OooOOO()Z
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/j66;->_elementDeserializer:Llyiahf/vczjk/e94;

    if-nez v0, :cond_0

    iget-object v0, p0, Llyiahf/vczjk/j66;->_elementTypeDeserializer:Llyiahf/vczjk/u3a;

    if-nez v0, :cond_0

    const/4 v0, 0x1

    return v0

    :cond_0
    const/4 v0, 0x0

    return v0
.end method

.method public final OoooOOO()Llyiahf/vczjk/e94;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/j66;->_elementDeserializer:Llyiahf/vczjk/e94;

    return-object v0
.end method

.method public final OoooOoO(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)[Ljava/lang/Object;
    .locals 5

    sget-object v0, Llyiahf/vczjk/gc4;->OooOo00:Llyiahf/vczjk/gc4;

    invoke-virtual {p2, v0}, Llyiahf/vczjk/eb4;->o0000Oo(Llyiahf/vczjk/gc4;)Z

    move-result v1

    const/4 v2, 0x0

    if-eqz v1, :cond_0

    sget-object v1, Llyiahf/vczjk/w72;->Oooo000:Llyiahf/vczjk/w72;

    invoke-virtual {p1, v1}, Llyiahf/vczjk/v72;->o0000(Llyiahf/vczjk/w72;)Z

    move-result v1

    if-eqz v1, :cond_0

    invoke-virtual {p2}, Llyiahf/vczjk/eb4;->o0000oO()Ljava/lang/String;

    move-result-object v1

    invoke-virtual {v1}, Ljava/lang/String;->length()I

    move-result v1

    if-nez v1, :cond_0

    return-object v2

    :cond_0
    iget-object v1, p0, Llyiahf/vczjk/ul1;->_unwrapSingle:Ljava/lang/Boolean;

    sget-object v3, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    const/4 v4, 0x0

    if-eq v1, v3, :cond_4

    if-nez v1, :cond_1

    sget-object v1, Llyiahf/vczjk/w72;->OooOoo:Llyiahf/vczjk/w72;

    invoke-virtual {p1, v1}, Llyiahf/vczjk/v72;->o0000(Llyiahf/vczjk/w72;)Z

    move-result v1

    if-eqz v1, :cond_1

    goto :goto_1

    :cond_1
    invoke-virtual {p2, v0}, Llyiahf/vczjk/eb4;->o0000Oo(Llyiahf/vczjk/gc4;)Z

    move-result v0

    if-eqz v0, :cond_3

    iget-object v0, p0, Llyiahf/vczjk/j66;->_elementClass:Ljava/lang/Class;

    const-class v1, Ljava/lang/Byte;

    if-ne v0, v1, :cond_3

    invoke-virtual {p1}, Llyiahf/vczjk/v72;->o00oO0O()Llyiahf/vczjk/z50;

    move-result-object p1

    invoke-virtual {p2, p1}, Llyiahf/vczjk/eb4;->OooOooo(Llyiahf/vczjk/z50;)[B

    move-result-object p1

    array-length p2, p1

    new-array p2, p2, [Ljava/lang/Byte;

    array-length v0, p1

    :goto_0
    if-ge v4, v0, :cond_2

    aget-byte v1, p1, v4

    invoke-static {v1}, Ljava/lang/Byte;->valueOf(B)Ljava/lang/Byte;

    move-result-object v1

    aput-object v1, p2, v4

    add-int/lit8 v4, v4, 0x1

    goto :goto_0

    :cond_2
    return-object p2

    :cond_3
    iget-object v0, p0, Llyiahf/vczjk/ul1;->_containerType:Llyiahf/vczjk/x64;

    invoke-virtual {v0}, Llyiahf/vczjk/x64;->OoooO()Ljava/lang/Class;

    move-result-object v0

    invoke-virtual {p1, v0, p2}, Llyiahf/vczjk/v72;->o000000o(Ljava/lang/Class;Llyiahf/vczjk/eb4;)V

    throw v2

    :cond_4
    :goto_1
    sget-object v0, Llyiahf/vczjk/gc4;->OooOoO0:Llyiahf/vczjk/gc4;

    invoke-virtual {p2, v0}, Llyiahf/vczjk/eb4;->o0000Oo(Llyiahf/vczjk/gc4;)Z

    move-result v0

    if-eqz v0, :cond_6

    iget-boolean p2, p0, Llyiahf/vczjk/ul1;->_skipNullValues:Z

    if-eqz p2, :cond_5

    sget-object p1, Llyiahf/vczjk/j66;->OooOOOO:[Ljava/lang/Object;

    return-object p1

    :cond_5
    iget-object p2, p0, Llyiahf/vczjk/ul1;->_nullProvider:Llyiahf/vczjk/u46;

    invoke-interface {p2, p1}, Llyiahf/vczjk/u46;->OooO0O0(Llyiahf/vczjk/v72;)Ljava/lang/Object;

    move-result-object p1

    goto :goto_2

    :cond_6
    iget-object v0, p0, Llyiahf/vczjk/j66;->_elementTypeDeserializer:Llyiahf/vczjk/u3a;

    if-nez v0, :cond_7

    iget-object v0, p0, Llyiahf/vczjk/j66;->_elementDeserializer:Llyiahf/vczjk/e94;

    invoke-virtual {v0, p1, p2}, Llyiahf/vczjk/e94;->OooO0Oo(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)Ljava/lang/Object;

    move-result-object p1

    goto :goto_2

    :cond_7
    iget-object v1, p0, Llyiahf/vczjk/j66;->_elementDeserializer:Llyiahf/vczjk/e94;

    invoke-virtual {v1, p2, p1, v0}, Llyiahf/vczjk/e94;->OooO0o(Llyiahf/vczjk/eb4;Llyiahf/vczjk/v72;Llyiahf/vczjk/u3a;)Ljava/lang/Object;

    move-result-object p1

    :goto_2
    iget-boolean p2, p0, Llyiahf/vczjk/j66;->_untyped:Z

    const/4 v0, 0x1

    if-eqz p2, :cond_8

    new-array p2, v0, [Ljava/lang/Object;

    goto :goto_3

    :cond_8
    iget-object p2, p0, Llyiahf/vczjk/j66;->_elementClass:Ljava/lang/Class;

    invoke-static {p2, v0}, Ljava/lang/reflect/Array;->newInstance(Ljava/lang/Class;I)Ljava/lang/Object;

    move-result-object p2

    check-cast p2, [Ljava/lang/Object;

    :goto_3
    aput-object p1, p2, v4

    return-object p2
.end method
