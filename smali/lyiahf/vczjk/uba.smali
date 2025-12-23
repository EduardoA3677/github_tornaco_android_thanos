.class public abstract Llyiahf/vczjk/uba;
.super Ljava/lang/Object;
.source "SourceFile"


# static fields
.field public static final OooO00o:J

.field public static final OooO0O0:Llyiahf/vczjk/pi7;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    const/4 v0, 0x0

    invoke-static {v0, v0, v0, v0}, Llyiahf/vczjk/uk1;->OooO0oo(IIII)J

    move-result-wide v0

    sput-wide v0, Llyiahf/vczjk/uba;->OooO00o:J

    sget-object v0, Llyiahf/vczjk/sq8;->OooO0OO:Llyiahf/vczjk/sq8;

    new-instance v0, Llyiahf/vczjk/pi7;

    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    sput-object v0, Llyiahf/vczjk/uba;->OooO0O0:Llyiahf/vczjk/pi7;

    return-void
.end method

.method public static final OooO00o(Llyiahf/vczjk/kv3;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/kv3;
    .locals 4

    check-cast p1, Llyiahf/vczjk/zf1;

    const v0, 0x40cd272a

    invoke-virtual {p1, v0}, Llyiahf/vczjk/zf1;->OoooOO0(I)V

    const/4 v0, 0x0

    if-eqz p0, :cond_0

    invoke-virtual {p1, v0}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    return-object p0

    :cond_0
    sget-object v1, Landroidx/compose/ui/platform/AndroidCompositionLocals_androidKt;->OooO0O0:Llyiahf/vczjk/l39;

    invoke-virtual {p1, v1}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Landroid/content/Context;

    const v2, -0x4a382b91

    invoke-virtual {p1, v2}, Llyiahf/vczjk/zf1;->OoooOO0(I)V

    invoke-virtual {p1, v1}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v2

    invoke-virtual {p1, p0}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v3

    or-int/2addr v2, v3

    invoke-virtual {p1}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v3

    if-nez v2, :cond_1

    sget-object v2, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    if-ne v3, v2, :cond_2

    :cond_1
    new-instance v2, Llyiahf/vczjk/jv3;

    invoke-direct {v2, v1}, Llyiahf/vczjk/jv3;-><init>(Landroid/content/Context;)V

    iput-object p0, v2, Llyiahf/vczjk/jv3;->OooO0OO:Ljava/lang/Object;

    invoke-virtual {v2}, Llyiahf/vczjk/jv3;->OooO00o()Llyiahf/vczjk/kv3;

    move-result-object v3

    invoke-virtual {p1, v3}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_2
    check-cast v3, Llyiahf/vczjk/kv3;

    invoke-virtual {p1, v0}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-virtual {p1, v0}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    return-object v3
.end method
