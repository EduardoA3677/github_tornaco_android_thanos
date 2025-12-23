.class public final synthetic Llyiahf/vczjk/a51;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Ljava/lang/Runnable;


# instance fields
.field public final synthetic OooOOO:Lgithub/tornaco/android/thanos/common/CommonFuncToggleAppListFilterActivity;

.field public final synthetic OooOOO0:I


# direct methods
.method public synthetic constructor <init>(Lgithub/tornaco/android/thanos/common/CommonFuncToggleAppListFilterActivity;I)V
    .locals 0

    iput p2, p0, Llyiahf/vczjk/a51;->OooOOO0:I

    iput-object p1, p0, Llyiahf/vczjk/a51;->OooOOO:Lgithub/tornaco/android/thanos/common/CommonFuncToggleAppListFilterActivity;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final run()V
    .locals 6

    iget-object v0, p0, Llyiahf/vczjk/a51;->OooOOO:Lgithub/tornaco/android/thanos/common/CommonFuncToggleAppListFilterActivity;

    const/4 v1, 0x0

    iget v2, p0, Llyiahf/vczjk/a51;->OooOOO0:I

    packed-switch v2, :pswitch_data_0

    sget v2, Lgithub/tornaco/android/thanos/common/CommonFuncToggleAppListFilterActivity;->OoooO00:I

    iget-object v0, v0, Lgithub/tornaco/android/thanos/common/BaseAppListFilterActivity;->Oooo0oO:Llyiahf/vczjk/t41;

    check-cast v0, Llyiahf/vczjk/g51;

    iget-object v2, v0, Llyiahf/vczjk/t41;->OooO0o0:Landroidx/databinding/ObservableArrayList;

    invoke-static {v2}, Llyiahf/vczjk/o76;->OooO00o(Ljava/lang/Iterable;)Llyiahf/vczjk/o76;

    move-result-object v2

    new-instance v3, Llyiahf/vczjk/f51;

    invoke-direct {v3, v0, v1}, Llyiahf/vczjk/f51;-><init>(Llyiahf/vczjk/g51;I)V

    new-instance v4, Llyiahf/vczjk/u76;

    invoke-direct {v4, v2, v3, v1}, Llyiahf/vczjk/u76;-><init>(Llyiahf/vczjk/o76;Ljava/lang/Object;I)V

    sget-object v1, Llyiahf/vczjk/s88;->OooO0OO:Llyiahf/vczjk/i88;

    invoke-virtual {v4, v1}, Llyiahf/vczjk/o76;->OooO0o(Llyiahf/vczjk/i88;)Llyiahf/vczjk/u76;

    move-result-object v1

    invoke-static {}, Llyiahf/vczjk/wf;->OooO00o()Llyiahf/vczjk/i88;

    move-result-object v2

    invoke-virtual {v1, v2}, Llyiahf/vczjk/o76;->OooO0O0(Llyiahf/vczjk/i88;)Llyiahf/vczjk/c86;

    move-result-object v1

    sget-object v2, Lgithub/tornaco/android/thanos/core/util/Rxs;->EMPTY_CONSUMER:Llyiahf/vczjk/nl1;

    sget-object v3, Lgithub/tornaco/android/thanos/core/util/Rxs;->ON_ERROR_LOGGING:Llyiahf/vczjk/nl1;

    new-instance v4, Llyiahf/vczjk/f51;

    const/4 v5, 0x1

    invoke-direct {v4, v0, v5}, Llyiahf/vczjk/f51;-><init>(Llyiahf/vczjk/g51;I)V

    invoke-virtual {v1, v2, v3, v4}, Llyiahf/vczjk/o76;->OooO0OO(Llyiahf/vczjk/nl1;Llyiahf/vczjk/nl1;Llyiahf/vczjk/o0oo0000;)Llyiahf/vczjk/sm4;

    move-result-object v1

    iget-object v0, v0, Llyiahf/vczjk/t41;->OooO0Oo:Llyiahf/vczjk/cg1;

    invoke-virtual {v0, v1}, Llyiahf/vczjk/cg1;->OooO0O0(Llyiahf/vczjk/nc2;)Z

    return-void

    :pswitch_0
    sget v2, Lgithub/tornaco/android/thanos/common/CommonFuncToggleAppListFilterActivity;->OoooO00:I

    iget-object v0, v0, Lgithub/tornaco/android/thanos/common/BaseAppListFilterActivity;->Oooo0oO:Llyiahf/vczjk/t41;

    check-cast v0, Llyiahf/vczjk/g51;

    iget-object v2, v0, Llyiahf/vczjk/t41;->OooO0o0:Landroidx/databinding/ObservableArrayList;

    invoke-static {v2}, Llyiahf/vczjk/o76;->OooO00o(Ljava/lang/Iterable;)Llyiahf/vczjk/o76;

    move-result-object v2

    new-instance v3, Llyiahf/vczjk/f51;

    const/4 v4, 0x2

    invoke-direct {v3, v0, v4}, Llyiahf/vczjk/f51;-><init>(Llyiahf/vczjk/g51;I)V

    new-instance v4, Llyiahf/vczjk/u76;

    invoke-direct {v4, v2, v3, v1}, Llyiahf/vczjk/u76;-><init>(Llyiahf/vczjk/o76;Ljava/lang/Object;I)V

    sget-object v1, Llyiahf/vczjk/s88;->OooO0OO:Llyiahf/vczjk/i88;

    invoke-virtual {v4, v1}, Llyiahf/vczjk/o76;->OooO0o(Llyiahf/vczjk/i88;)Llyiahf/vczjk/u76;

    move-result-object v1

    invoke-static {}, Llyiahf/vczjk/wf;->OooO00o()Llyiahf/vczjk/i88;

    move-result-object v2

    invoke-virtual {v1, v2}, Llyiahf/vczjk/o76;->OooO0O0(Llyiahf/vczjk/i88;)Llyiahf/vczjk/c86;

    move-result-object v1

    sget-object v2, Lgithub/tornaco/android/thanos/core/util/Rxs;->EMPTY_CONSUMER:Llyiahf/vczjk/nl1;

    sget-object v3, Lgithub/tornaco/android/thanos/core/util/Rxs;->ON_ERROR_LOGGING:Llyiahf/vczjk/nl1;

    new-instance v4, Llyiahf/vczjk/f51;

    const/4 v5, 0x3

    invoke-direct {v4, v0, v5}, Llyiahf/vczjk/f51;-><init>(Llyiahf/vczjk/g51;I)V

    invoke-virtual {v1, v2, v3, v4}, Llyiahf/vczjk/o76;->OooO0OO(Llyiahf/vczjk/nl1;Llyiahf/vczjk/nl1;Llyiahf/vczjk/o0oo0000;)Llyiahf/vczjk/sm4;

    move-result-object v1

    iget-object v0, v0, Llyiahf/vczjk/t41;->OooO0Oo:Llyiahf/vczjk/cg1;

    invoke-virtual {v0, v1}, Llyiahf/vczjk/cg1;->OooO0O0(Llyiahf/vczjk/nc2;)Z

    return-void

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
