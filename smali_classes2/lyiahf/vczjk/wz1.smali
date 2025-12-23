.class public final synthetic Llyiahf/vczjk/wz1;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field public final synthetic OooOOO:Lgithub/tornaco/thanos/android/module/profile/engine/DateTimeEngineActivity;

.field public final synthetic OooOOO0:I


# direct methods
.method public synthetic constructor <init>(Lgithub/tornaco/thanos/android/module/profile/engine/DateTimeEngineActivity;II)V
    .locals 0

    iput p3, p0, Llyiahf/vczjk/wz1;->OooOOO0:I

    iput-object p1, p0, Llyiahf/vczjk/wz1;->OooOOO:Lgithub/tornaco/thanos/android/module/profile/engine/DateTimeEngineActivity;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 3

    sget-object v0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    iget-object v1, p0, Llyiahf/vczjk/wz1;->OooOOO:Lgithub/tornaco/thanos/android/module/profile/engine/DateTimeEngineActivity;

    iget v2, p0, Llyiahf/vczjk/wz1;->OooOOO0:I

    check-cast p1, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Integer;

    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    packed-switch v2, :pswitch_data_0

    const/16 p2, 0x9

    invoke-static {p2}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result p2

    invoke-static {v1, p1, p2}, Llyiahf/vczjk/bua;->OooO0OO(Lgithub/tornaco/thanos/android/module/profile/engine/DateTimeEngineActivity;Llyiahf/vczjk/rf1;I)V

    return-object v0

    :pswitch_0
    sget p2, Lgithub/tornaco/thanos/android/module/profile/engine/DateTimeEngineActivity;->OoooO0O:I

    const/4 p2, 0x1

    invoke-static {p2}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result p2

    invoke-virtual {v1, p2, p1}, Lgithub/tornaco/thanos/android/module/profile/engine/DateTimeEngineActivity;->OooOoOO(ILlyiahf/vczjk/rf1;)V

    return-object v0

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
