.class public final Llyiahf/vczjk/ci0;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/le3;


# instance fields
.field final synthetic $boundsProvider:Llyiahf/vczjk/le3;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/le3;"
        }
    .end annotation
.end field

.field final synthetic $childCoordinates:Llyiahf/vczjk/xn4;

.field final synthetic this$0:Llyiahf/vczjk/di0;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/di0;Llyiahf/vczjk/v16;Llyiahf/vczjk/ph0;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/ci0;->this$0:Llyiahf/vczjk/di0;

    iput-object p2, p0, Llyiahf/vczjk/ci0;->$childCoordinates:Llyiahf/vczjk/xn4;

    iput-object p3, p0, Llyiahf/vczjk/ci0;->$boundsProvider:Llyiahf/vczjk/le3;

    const/4 p1, 0x0

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO00o()Ljava/lang/Object;
    .locals 6

    iget-object v0, p0, Llyiahf/vczjk/ci0;->this$0:Llyiahf/vczjk/di0;

    iget-object v1, p0, Llyiahf/vczjk/ci0;->$childCoordinates:Llyiahf/vczjk/xn4;

    iget-object v2, p0, Llyiahf/vczjk/ci0;->$boundsProvider:Llyiahf/vczjk/le3;

    invoke-static {v0, v1, v2}, Llyiahf/vczjk/di0;->o00000OO(Llyiahf/vczjk/di0;Llyiahf/vczjk/xn4;Llyiahf/vczjk/le3;)Llyiahf/vczjk/wj7;

    move-result-object v0

    if-eqz v0, :cond_1

    iget-object v1, p0, Llyiahf/vczjk/ci0;->this$0:Llyiahf/vczjk/di0;

    iget-object v1, v1, Llyiahf/vczjk/di0;->OooOoOO:Llyiahf/vczjk/um1;

    iget-wide v2, v1, Llyiahf/vczjk/um1;->Oooo0:J

    const-wide/16 v4, 0x0

    invoke-static {v2, v3, v4, v5}, Llyiahf/vczjk/b24;->OooO00o(JJ)Z

    move-result v2

    if-eqz v2, :cond_0

    const-string v2, "Expected BringIntoViewRequester to not be used before parents are placed."

    invoke-static {v2}, Llyiahf/vczjk/sz3;->OooO0OO(Ljava/lang/String;)V

    :cond_0
    iget-wide v2, v1, Llyiahf/vczjk/um1;->Oooo0:J

    invoke-virtual {v1, v0, v2, v3}, Llyiahf/vczjk/um1;->o00000oO(Llyiahf/vczjk/wj7;J)J

    move-result-wide v1

    const-wide v3, -0x7fffffff80000000L    # -1.0609978955E-314

    xor-long/2addr v1, v3

    invoke-virtual {v0, v1, v2}, Llyiahf/vczjk/wj7;->OooO(J)Llyiahf/vczjk/wj7;

    move-result-object v0

    return-object v0

    :cond_1
    const/4 v0, 0x0

    return-object v0
.end method
