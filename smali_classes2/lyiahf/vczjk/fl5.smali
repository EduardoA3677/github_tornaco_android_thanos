.class public final synthetic Llyiahf/vczjk/fl5;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Landroid/view/View$OnClickListener;


# instance fields
.field public final synthetic OooOOO:Llyiahf/vczjk/ly2;

.field public final synthetic OooOOO0:I

.field public final synthetic OooOOOO:Llyiahf/vczjk/el5;


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/ly2;Llyiahf/vczjk/el5;I)V
    .locals 0

    iput p3, p0, Llyiahf/vczjk/fl5;->OooOOO0:I

    iput-object p1, p0, Llyiahf/vczjk/fl5;->OooOOO:Llyiahf/vczjk/ly2;

    iput-object p2, p0, Llyiahf/vczjk/fl5;->OooOOOO:Llyiahf/vczjk/el5;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final onClick(Landroid/view/View;)V
    .locals 1

    iget p1, p0, Llyiahf/vczjk/fl5;->OooOOO0:I

    packed-switch p1, :pswitch_data_0

    iget-object p1, p0, Llyiahf/vczjk/fl5;->OooOOO:Llyiahf/vczjk/ly2;

    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    iget-object v0, p0, Llyiahf/vczjk/fl5;->OooOOOO:Llyiahf/vczjk/el5;

    iget-object v0, v0, Llyiahf/vczjk/el5;->OooO00o:Ljava/lang/String;

    invoke-virtual {p1, v0}, Llyiahf/vczjk/ly2;->OooOO0o(Ljava/lang/String;)V

    return-void

    :pswitch_0
    iget-object p1, p0, Llyiahf/vczjk/fl5;->OooOOO:Llyiahf/vczjk/ly2;

    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    iget-object v0, p0, Llyiahf/vczjk/fl5;->OooOOOO:Llyiahf/vczjk/el5;

    iget-object v0, v0, Llyiahf/vczjk/el5;->OooO00o:Ljava/lang/String;

    invoke-virtual {p1, v0}, Llyiahf/vczjk/ly2;->OooOO0o(Ljava/lang/String;)V

    return-void

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
