.class public final Llyiahf/vczjk/up2;
.super Llyiahf/vczjk/wt9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/xo1;


# static fields
.field private static final serialVersionUID:J = 0x1L


# instance fields
.field protected final _serializeAsIndex:Ljava/lang/Boolean;

.field protected final _values:Llyiahf/vczjk/aq2;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/aq2;Ljava/lang/Boolean;)V
    .locals 1

    invoke-virtual {p1}, Llyiahf/vczjk/aq2;->OooO0O0()Ljava/lang/Class;

    move-result-object v0

    invoke-direct {p0, v0}, Llyiahf/vczjk/wt9;-><init>(Ljava/lang/Class;)V

    iput-object p1, p0, Llyiahf/vczjk/up2;->_values:Llyiahf/vczjk/aq2;

    iput-object p2, p0, Llyiahf/vczjk/up2;->_serializeAsIndex:Ljava/lang/Boolean;

    return-void
.end method

.method public static OooOOOO(Ljava/lang/Class;Llyiahf/vczjk/q94;ZLjava/lang/Boolean;)Ljava/lang/Boolean;
    .locals 2

    if-nez p1, :cond_0

    const/4 p1, 0x0

    goto :goto_0

    :cond_0
    invoke-virtual {p1}, Llyiahf/vczjk/q94;->OooO0o()Llyiahf/vczjk/p94;

    move-result-object p1

    :goto_0
    if-nez p1, :cond_1

    goto :goto_4

    :cond_1
    sget-object v0, Llyiahf/vczjk/p94;->OooOOO0:Llyiahf/vczjk/p94;

    if-eq p1, v0, :cond_8

    sget-object v0, Llyiahf/vczjk/p94;->OooOOOO:Llyiahf/vczjk/p94;

    if-ne p1, v0, :cond_2

    goto :goto_4

    :cond_2
    sget-object p3, Llyiahf/vczjk/p94;->OooOo0:Llyiahf/vczjk/p94;

    if-eq p1, p3, :cond_7

    sget-object p3, Llyiahf/vczjk/p94;->OooOOO:Llyiahf/vczjk/p94;

    if-ne p1, p3, :cond_3

    goto :goto_3

    :cond_3
    invoke-virtual {p1}, Llyiahf/vczjk/p94;->OooO00o()Z

    move-result p3

    if-nez p3, :cond_6

    sget-object p3, Llyiahf/vczjk/p94;->OooOOOo:Llyiahf/vczjk/p94;

    if-ne p1, p3, :cond_4

    goto :goto_2

    :cond_4
    new-instance p3, Ljava/lang/IllegalArgumentException;

    invoke-virtual {p0}, Ljava/lang/Class;->getName()Ljava/lang/String;

    move-result-object p0

    if-eqz p2, :cond_5

    const-string p2, "class"

    goto :goto_1

    :cond_5
    const-string p2, "property"

    :goto_1
    new-instance v0, Ljava/lang/StringBuilder;

    const-string v1, "Unsupported serialization shape ("

    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string p1, ") for Enum "

    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string p0, ", not supported as "

    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string p0, " annotation"

    invoke-static {v0, p2, p0}, Llyiahf/vczjk/ix8;->OooOO0(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object p0

    invoke-direct {p3, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p3

    :cond_6
    :goto_2
    sget-object p0, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    return-object p0

    :cond_7
    :goto_3
    sget-object p0, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    return-object p0

    :cond_8
    :goto_4
    return-object p3
.end method


# virtual methods
.method public final OooO0O0(Llyiahf/vczjk/tg8;Llyiahf/vczjk/db0;)Llyiahf/vczjk/zb4;
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/b59;->_handledType:Ljava/lang/Class;

    invoke-static {p1, p2, v0}, Llyiahf/vczjk/b59;->OooOO0O(Llyiahf/vczjk/tg8;Llyiahf/vczjk/db0;Ljava/lang/Class;)Llyiahf/vczjk/q94;

    move-result-object p1

    if-eqz p1, :cond_0

    iget-object p2, p0, Llyiahf/vczjk/b59;->_handledType:Ljava/lang/Class;

    const/4 v0, 0x0

    iget-object v1, p0, Llyiahf/vczjk/up2;->_serializeAsIndex:Ljava/lang/Boolean;

    invoke-static {p2, p1, v0, v1}, Llyiahf/vczjk/up2;->OooOOOO(Ljava/lang/Class;Llyiahf/vczjk/q94;ZLjava/lang/Boolean;)Ljava/lang/Boolean;

    move-result-object p1

    iget-object p2, p0, Llyiahf/vczjk/up2;->_serializeAsIndex:Ljava/lang/Boolean;

    if-eq p1, p2, :cond_0

    new-instance p2, Llyiahf/vczjk/up2;

    iget-object v0, p0, Llyiahf/vczjk/up2;->_values:Llyiahf/vczjk/aq2;

    invoke-direct {p2, v0, p1}, Llyiahf/vczjk/up2;-><init>(Llyiahf/vczjk/aq2;Ljava/lang/Boolean;)V

    return-object p2

    :cond_0
    return-object p0
.end method

.method public final OooO0o(Ljava/lang/Object;Llyiahf/vczjk/u94;Llyiahf/vczjk/tg8;)V
    .locals 1

    check-cast p1, Ljava/lang/Enum;

    iget-object v0, p0, Llyiahf/vczjk/up2;->_serializeAsIndex:Ljava/lang/Boolean;

    if-eqz v0, :cond_0

    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v0

    goto :goto_0

    :cond_0
    sget-object v0, Llyiahf/vczjk/ig8;->OooOoO:Llyiahf/vczjk/ig8;

    invoke-virtual {p3, v0}, Llyiahf/vczjk/tg8;->o0000Ooo(Llyiahf/vczjk/ig8;)Z

    move-result v0

    :goto_0
    if-eqz v0, :cond_1

    invoke-virtual {p1}, Ljava/lang/Enum;->ordinal()I

    move-result p1

    invoke-virtual {p2, p1}, Llyiahf/vczjk/u94;->o0000oo(I)V

    return-void

    :cond_1
    sget-object v0, Llyiahf/vczjk/ig8;->OooOoO0:Llyiahf/vczjk/ig8;

    invoke-virtual {p3, v0}, Llyiahf/vczjk/tg8;->o0000Ooo(Llyiahf/vczjk/ig8;)Z

    move-result p3

    if-eqz p3, :cond_2

    invoke-virtual {p1}, Ljava/lang/Enum;->toString()Ljava/lang/String;

    move-result-object p1

    invoke-virtual {p2, p1}, Llyiahf/vczjk/u94;->o0000ooO(Ljava/lang/String;)V

    return-void

    :cond_2
    iget-object p3, p0, Llyiahf/vczjk/up2;->_values:Llyiahf/vczjk/aq2;

    invoke-virtual {p3, p1}, Llyiahf/vczjk/aq2;->OooO0OO(Ljava/lang/Enum;)Llyiahf/vczjk/fg8;

    move-result-object p1

    invoke-virtual {p2, p1}, Llyiahf/vczjk/u94;->o000(Llyiahf/vczjk/fg8;)V

    return-void
.end method
