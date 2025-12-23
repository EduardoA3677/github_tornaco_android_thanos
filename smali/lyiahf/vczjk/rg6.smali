.class public abstract Llyiahf/vczjk/rg6;
.super Ljava/lang/Object;
.source "SourceFile"


# static fields
.field public static final OooO00o:Llyiahf/vczjk/jh1;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    sget-object v0, Llyiahf/vczjk/k65;->OooOo:Llyiahf/vczjk/k65;

    new-instance v1, Llyiahf/vczjk/jh1;

    invoke-direct {v1, v0}, Llyiahf/vczjk/jh1;-><init>(Llyiahf/vczjk/oe3;)V

    sput-object v1, Llyiahf/vczjk/rg6;->OooO00o:Llyiahf/vczjk/jh1;

    return-void
.end method

.method public static final OooO00o(Llyiahf/vczjk/rf1;)Llyiahf/vczjk/qg6;
    .locals 10

    check-cast p0, Llyiahf/vczjk/zf1;

    const v0, 0x10dd5ab0

    invoke-virtual {p0, v0}, Llyiahf/vczjk/zf1;->OoooO(I)V

    sget-object v0, Llyiahf/vczjk/rg6;->OooO00o:Llyiahf/vczjk/jh1;

    invoke-virtual {p0, v0}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/dd;

    const/4 v1, 0x0

    if-nez v0, :cond_0

    invoke-virtual {p0, v1}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    const/4 p0, 0x0

    return-object p0

    :cond_0
    invoke-virtual {p0, v0}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v2

    invoke-virtual {p0}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v3

    if-nez v2, :cond_1

    sget-object v2, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    if-ne v3, v2, :cond_2

    :cond_1
    new-instance v4, Llyiahf/vczjk/cd;

    iget-object v5, v0, Llyiahf/vczjk/dd;->OooO00o:Landroid/content/Context;

    iget-object v9, v0, Llyiahf/vczjk/dd;->OooO0Oo:Llyiahf/vczjk/di6;

    iget-object v6, v0, Llyiahf/vczjk/dd;->OooO0O0:Llyiahf/vczjk/f62;

    iget-wide v7, v0, Llyiahf/vczjk/dd;->OooO0OO:J

    invoke-direct/range {v4 .. v9}, Llyiahf/vczjk/cd;-><init>(Landroid/content/Context;Llyiahf/vczjk/f62;JLlyiahf/vczjk/di6;)V

    invoke-virtual {p0, v4}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    move-object v3, v4

    :cond_2
    check-cast v3, Llyiahf/vczjk/qg6;

    invoke-virtual {p0, v1}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    return-object v3
.end method
