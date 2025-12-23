.class public final synthetic Llyiahf/vczjk/na2;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/le3;


# instance fields
.field public final synthetic OooOOO:Llyiahf/vczjk/zh1;

.field public final synthetic OooOOO0:I


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/zh1;I)V
    .locals 0

    iput p2, p0, Llyiahf/vczjk/na2;->OooOOO0:I

    iput-object p1, p0, Llyiahf/vczjk/na2;->OooOOO:Llyiahf/vczjk/zh1;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final OooO00o()Ljava/lang/Object;
    .locals 5

    const/4 v0, 0x0

    const/4 v1, 0x1

    sget-object v2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    iget-object v3, p0, Llyiahf/vczjk/na2;->OooOOO:Llyiahf/vczjk/zh1;

    iget v4, p0, Llyiahf/vczjk/na2;->OooOOO0:I

    packed-switch v4, :pswitch_data_0

    invoke-virtual {v3, v1}, Llyiahf/vczjk/w41;->OooO0OO(Z)V

    return-object v2

    :pswitch_0
    invoke-virtual {v3, v1}, Llyiahf/vczjk/w41;->OooO0OO(Z)V

    return-object v2

    :pswitch_1
    sget v0, Lnow/fortuitous/thanos/recovery/RecoveryUtilsActivity;->OoooO0O:I

    invoke-virtual {v3, v1}, Llyiahf/vczjk/w41;->OooO0OO(Z)V

    return-object v2

    :pswitch_2
    invoke-virtual {v3, v0}, Llyiahf/vczjk/w41;->OooO0OO(Z)V

    return-object v2

    :pswitch_3
    invoke-virtual {v3, v0}, Llyiahf/vczjk/w41;->OooO0OO(Z)V

    return-object v2

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
