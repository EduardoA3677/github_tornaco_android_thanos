.class public abstract Llyiahf/vczjk/pq8;
.super Ljava/lang/Object;
.source "SourceFile"


# direct methods
.method static constructor <clinit>()V
    .locals 3

    const/4 v0, 0x7

    const/4 v1, 0x0

    const/4 v2, 0x0

    invoke-static {v1, v1, v2, v0}, Llyiahf/vczjk/ng0;->OoooOoo(FFLjava/lang/Object;I)Llyiahf/vczjk/wz8;

    return-void
.end method

.method public static final OooO00o(JLlyiahf/vczjk/wl;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/p29;
    .locals 9

    invoke-static {p0, p1}, Llyiahf/vczjk/n21;->OooO0o(J)Llyiahf/vczjk/a31;

    move-result-object v0

    move-object v6, p3

    check-cast v6, Llyiahf/vczjk/zf1;

    invoke-virtual {v6, v0}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result p3

    invoke-virtual {v6}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v0

    if-nez p3, :cond_0

    sget-object p3, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    if-ne v0, p3, :cond_1

    :cond_0
    invoke-static {p0, p1}, Llyiahf/vczjk/n21;->OooO0o(J)Llyiahf/vczjk/a31;

    move-result-object p3

    sget-object v0, Llyiahf/vczjk/ke0;->OooOOoo:Llyiahf/vczjk/ke0;

    new-instance v1, Llyiahf/vczjk/i31;

    invoke-direct {v1, p3}, Llyiahf/vczjk/i31;-><init>(Llyiahf/vczjk/a31;)V

    sget-object p3, Llyiahf/vczjk/gda;->OooO00o:Llyiahf/vczjk/n1a;

    new-instance p3, Llyiahf/vczjk/n1a;

    invoke-direct {p3, v0, v1}, Llyiahf/vczjk/n1a;-><init>(Llyiahf/vczjk/oe3;Llyiahf/vczjk/oe3;)V

    invoke-virtual {v6, p3}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    move-object v0, p3

    :cond_1
    move-object v2, v0

    check-cast v2, Llyiahf/vczjk/m1a;

    new-instance v1, Llyiahf/vczjk/n21;

    invoke-direct {v1, p0, p1}, Llyiahf/vczjk/n21;-><init>(J)V

    const/16 v8, 0x8

    const/4 v4, 0x0

    const-string v5, "ColorAnimation"

    const/4 v7, 0x0

    move-object v3, p2

    invoke-static/range {v1 .. v8}, Llyiahf/vczjk/ti;->OooO0OO(Ljava/lang/Object;Llyiahf/vczjk/m1a;Llyiahf/vczjk/wl;Ljava/lang/Float;Ljava/lang/String;Llyiahf/vczjk/rf1;II)Llyiahf/vczjk/p29;

    move-result-object p0

    return-object p0
.end method
