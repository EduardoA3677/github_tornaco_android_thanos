.class public final Llyiahf/vczjk/ce0;
.super Llyiahf/vczjk/wt9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/xo1;


# static fields
.field private static final serialVersionUID:J = 0x1L


# instance fields
.field protected final _forPrimitive:Z


# direct methods
.method public constructor <init>(Z)V
    .locals 1

    if-eqz p1, :cond_0

    sget-object v0, Ljava/lang/Boolean;->TYPE:Ljava/lang/Class;

    goto :goto_0

    :cond_0
    const-class v0, Ljava/lang/Boolean;

    :goto_0
    invoke-direct {p0, v0}, Llyiahf/vczjk/wt9;-><init>(Ljava/lang/Class;)V

    iput-boolean p1, p0, Llyiahf/vczjk/ce0;->_forPrimitive:Z

    return-void
.end method


# virtual methods
.method public final OooO0O0(Llyiahf/vczjk/tg8;Llyiahf/vczjk/db0;)Llyiahf/vczjk/zb4;
    .locals 1

    const-class v0, Ljava/lang/Boolean;

    invoke-static {p1, p2, v0}, Llyiahf/vczjk/b59;->OooOO0O(Llyiahf/vczjk/tg8;Llyiahf/vczjk/db0;Ljava/lang/Class;)Llyiahf/vczjk/q94;

    move-result-object p1

    if-eqz p1, :cond_0

    invoke-virtual {p1}, Llyiahf/vczjk/q94;->OooO0o()Llyiahf/vczjk/p94;

    move-result-object p1

    invoke-virtual {p1}, Llyiahf/vczjk/p94;->OooO00o()Z

    move-result p1

    if-nez p1, :cond_0

    new-instance p1, Llyiahf/vczjk/de0;

    iget-boolean p2, p0, Llyiahf/vczjk/ce0;->_forPrimitive:Z

    invoke-direct {p1, p2}, Llyiahf/vczjk/de0;-><init>(Z)V

    return-object p1

    :cond_0
    return-object p0
.end method

.method public final OooO0o(Ljava/lang/Object;Llyiahf/vczjk/u94;Llyiahf/vczjk/tg8;)V
    .locals 0

    sget-object p3, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    invoke-virtual {p3, p1}, Ljava/lang/Boolean;->equals(Ljava/lang/Object;)Z

    move-result p1

    xor-int/lit8 p1, p1, 0x1

    invoke-virtual {p2, p1}, Llyiahf/vczjk/u94;->o0000oo(I)V

    return-void
.end method

.method public final OooO0oO(Ljava/lang/Object;Llyiahf/vczjk/u94;Llyiahf/vczjk/tg8;Llyiahf/vczjk/d5a;)V
    .locals 0

    sget-object p3, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    invoke-virtual {p3, p1}, Ljava/lang/Boolean;->equals(Ljava/lang/Object;)Z

    move-result p1

    invoke-virtual {p2, p1}, Llyiahf/vczjk/u94;->o000OOo(Z)V

    return-void
.end method
