.class public final Llyiahf/vczjk/o000O00O;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Landroid/view/View$OnClickListener;


# instance fields
.field public final synthetic OooOOO:Llyiahf/vczjk/o000OOo0;

.field public final synthetic OooOOO0:I


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/o000OOo0;I)V
    .locals 0

    iput p2, p0, Llyiahf/vczjk/o000O00O;->OooOOO0:I

    iput-object p1, p0, Llyiahf/vczjk/o000O00O;->OooOOO:Llyiahf/vczjk/o000OOo0;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final onClick(Landroid/view/View;)V
    .locals 1

    iget p1, p0, Llyiahf/vczjk/o000O00O;->OooOOO0:I

    packed-switch p1, :pswitch_data_0

    iget-object p1, p0, Llyiahf/vczjk/o000O00O;->OooOOO:Llyiahf/vczjk/o000OOo0;

    invoke-virtual {p1}, Llyiahf/vczjk/o000OOo0;->OooOOO0()V

    return-void

    :pswitch_0
    iget-object p1, p0, Llyiahf/vczjk/o000O00O;->OooOOO:Llyiahf/vczjk/o000OOo0;

    invoke-virtual {p1}, Llyiahf/vczjk/o000OOo0;->OooOOO0()V

    return-void

    :pswitch_1
    iget-object p1, p0, Llyiahf/vczjk/o000O00O;->OooOOO:Llyiahf/vczjk/o000OOo0;

    iget-object p1, p1, Llyiahf/vczjk/o000OOo0;->OooOo0:Llyiahf/vczjk/o000OO00;

    if-eqz p1, :cond_0

    check-cast p1, Lcom/nononsenseapps/filepicker/AbsFilePickerActivity;

    const/4 v0, 0x0

    invoke-virtual {p1, v0}, Landroid/app/Activity;->setResult(I)V

    invoke-virtual {p1}, Landroid/app/Activity;->finish()V

    :cond_0
    return-void

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
