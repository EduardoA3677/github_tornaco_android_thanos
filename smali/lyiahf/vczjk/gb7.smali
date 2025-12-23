.class public abstract Llyiahf/vczjk/gb7;
.super Ljava/lang/Object;
.source "SourceFile"


# virtual methods
.method public final OooO00o(Llyiahf/vczjk/x64;Llyiahf/vczjk/tg8;Llyiahf/vczjk/db0;)Llyiahf/vczjk/a27;
    .locals 2

    invoke-virtual {p2, p1, p3}, Llyiahf/vczjk/tg8;->o00Ooo(Llyiahf/vczjk/x64;Llyiahf/vczjk/db0;)Llyiahf/vczjk/zb4;

    move-result-object p2

    new-instance p3, Llyiahf/vczjk/a27;

    invoke-virtual {p1}, Llyiahf/vczjk/x64;->OoooO()Ljava/lang/Class;

    move-result-object p1

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/gb7;->OooO0O0(Ljava/lang/Class;Llyiahf/vczjk/zb4;)Llyiahf/vczjk/gb7;

    move-result-object p1

    const/16 v0, 0x1a

    const/4 v1, 0x0

    invoke-direct {p3, v0, p2, p1, v1}, Llyiahf/vczjk/a27;-><init>(ILjava/lang/Object;Ljava/lang/Object;Z)V

    return-object p3
.end method

.method public abstract OooO0O0(Ljava/lang/Class;Llyiahf/vczjk/zb4;)Llyiahf/vczjk/gb7;
.end method

.method public abstract OooO0OO(Ljava/lang/Class;)Llyiahf/vczjk/zb4;
.end method
