.class public final synthetic Llyiahf/vczjk/ooooO0O0;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Lutil/Consumer;


# instance fields
.field public final synthetic OooO00o:I

.field public final synthetic OooO0O0:Ljava/util/ArrayList;

.field public final synthetic OooO0OO:Llyiahf/vczjk/c17;


# direct methods
.method public synthetic constructor <init>(Ljava/util/ArrayList;Llyiahf/vczjk/c17;I)V
    .locals 0

    iput p3, p0, Llyiahf/vczjk/ooooO0O0;->OooO00o:I

    iput-object p1, p0, Llyiahf/vczjk/ooooO0O0;->OooO0O0:Ljava/util/ArrayList;

    iput-object p2, p0, Llyiahf/vczjk/ooooO0O0;->OooO0OO:Llyiahf/vczjk/c17;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final accept(Ljava/lang/Object;)V
    .locals 2

    iget v0, p0, Llyiahf/vczjk/ooooO0O0;->OooO00o:I

    packed-switch v0, :pswitch_data_0

    check-cast p1, Landroid/app/ActivityManager$RunningServiceInfo;

    iget-object v0, p0, Llyiahf/vczjk/ooooO0O0;->OooO0O0:Ljava/util/ArrayList;

    iget-object v1, p0, Llyiahf/vczjk/ooooO0O0;->OooO0OO:Llyiahf/vczjk/c17;

    invoke-static {v0, v1, p1}, Llyiahf/vczjk/a;->OoooO00(Ljava/util/ArrayList;Llyiahf/vczjk/c17;Landroid/app/ActivityManager$RunningServiceInfo;)V

    return-void

    :pswitch_0
    check-cast p1, Lgithub/tornaco/android/thanos/core/app/RunningAppProcessInfoCompat;

    iget-object v0, p0, Llyiahf/vczjk/ooooO0O0;->OooO0O0:Ljava/util/ArrayList;

    iget-object v1, p0, Llyiahf/vczjk/ooooO0O0;->OooO0OO:Llyiahf/vczjk/c17;

    invoke-static {v0, v1, p1}, Llyiahf/vczjk/a;->Oooo(Ljava/util/ArrayList;Llyiahf/vczjk/c17;Lgithub/tornaco/android/thanos/core/app/RunningAppProcessInfoCompat;)V

    return-void

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
