.class public final Llyiahf/vczjk/wy9;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field final synthetic $durationScale:F

.field final synthetic this$0:Llyiahf/vczjk/bz9;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/bz9;"
        }
    .end annotation
.end field


# direct methods
.method public constructor <init>(Llyiahf/vczjk/bz9;F)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/wy9;->this$0:Llyiahf/vczjk/bz9;

    iput p2, p0, Llyiahf/vczjk/wy9;->$durationScale:F

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 7

    check-cast p1, Ljava/lang/Number;

    invoke-virtual {p1}, Ljava/lang/Number;->longValue()J

    move-result-wide v0

    iget-object p1, p0, Llyiahf/vczjk/wy9;->this$0:Llyiahf/vczjk/bz9;

    invoke-virtual {p1}, Llyiahf/vczjk/bz9;->OooO()Z

    move-result p1

    if-nez p1, :cond_3

    iget-object p1, p0, Llyiahf/vczjk/wy9;->this$0:Llyiahf/vczjk/bz9;

    iget v2, p0, Llyiahf/vczjk/wy9;->$durationScale:F

    iget-object v3, p1, Llyiahf/vczjk/bz9;->OooO0oO:Llyiahf/vczjk/xv8;

    iget-object v4, v3, Llyiahf/vczjk/xv8;->OooOOOO:Llyiahf/vczjk/d39;

    check-cast v4, Llyiahf/vczjk/cw8;

    invoke-static {v4, v3}, Llyiahf/vczjk/vv8;->OooOo00(Llyiahf/vczjk/d39;Llyiahf/vczjk/b39;)Llyiahf/vczjk/d39;

    move-result-object v3

    check-cast v3, Llyiahf/vczjk/cw8;

    iget-wide v3, v3, Llyiahf/vczjk/cw8;->OooO0OO:J

    const-wide/high16 v5, -0x8000000000000000L

    cmp-long v3, v3, v5

    iget-object v4, p1, Llyiahf/vczjk/bz9;->OooO0oO:Llyiahf/vczjk/xv8;

    if-nez v3, :cond_0

    invoke-virtual {v4, v0, v1}, Llyiahf/vczjk/xv8;->OooOOoo(J)V

    iget-object v3, p1, Llyiahf/vczjk/bz9;->OooO00o:Llyiahf/vczjk/tz9;

    iget-object v3, v3, Llyiahf/vczjk/tz9;->OooO00o:Llyiahf/vczjk/qs5;

    sget-object v5, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    check-cast v3, Llyiahf/vczjk/fw8;

    invoke-virtual {v3, v5}, Llyiahf/vczjk/fw8;->setValue(Ljava/lang/Object;)V

    :cond_0
    iget-object v3, v4, Llyiahf/vczjk/xv8;->OooOOOO:Llyiahf/vczjk/d39;

    check-cast v3, Llyiahf/vczjk/cw8;

    invoke-static {v3, v4}, Llyiahf/vczjk/vv8;->OooOo00(Llyiahf/vczjk/d39;Llyiahf/vczjk/b39;)Llyiahf/vczjk/d39;

    move-result-object v3

    check-cast v3, Llyiahf/vczjk/cw8;

    iget-wide v3, v3, Llyiahf/vczjk/cw8;->OooO0OO:J

    sub-long/2addr v0, v3

    const/4 v3, 0x0

    cmpg-float v3, v2, v3

    if-nez v3, :cond_1

    goto :goto_0

    :cond_1
    long-to-double v0, v0

    float-to-double v4, v2

    div-double/2addr v0, v4

    invoke-static {v0, v1}, Llyiahf/vczjk/ye5;->Oooo00o(D)J

    move-result-wide v0

    :goto_0
    invoke-virtual {p1, v0, v1}, Llyiahf/vczjk/bz9;->OooOOOo(J)V

    if-nez v3, :cond_2

    const/4 v2, 0x1

    goto :goto_1

    :cond_2
    const/4 v2, 0x0

    :goto_1
    invoke-virtual {p1, v0, v1, v2}, Llyiahf/vczjk/bz9;->OooOO0(JZ)V

    :cond_3
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
