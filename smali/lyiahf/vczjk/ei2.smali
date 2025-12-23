.class public final synthetic Llyiahf/vczjk/ei2;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/le3;


# instance fields
.field public final synthetic OooOOO:Llyiahf/vczjk/ki2;

.field public final synthetic OooOOO0:I


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/ki2;I)V
    .locals 0

    iput p2, p0, Llyiahf/vczjk/ei2;->OooOOO0:I

    iput-object p1, p0, Llyiahf/vczjk/ei2;->OooOOO:Llyiahf/vczjk/ki2;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final OooO00o()Ljava/lang/Object;
    .locals 3

    iget v0, p0, Llyiahf/vczjk/ei2;->OooOOO0:I

    packed-switch v0, :pswitch_data_0

    iget-object v0, p0, Llyiahf/vczjk/ei2;->OooOOO:Llyiahf/vczjk/ki2;

    iget-object v0, v0, Llyiahf/vczjk/ki2;->OooO00o:Llyiahf/vczjk/h1a;

    return-object v0

    :pswitch_0
    iget-object v0, p0, Llyiahf/vczjk/ei2;->OooOOO:Llyiahf/vczjk/ki2;

    iget-object v1, v0, Llyiahf/vczjk/ki2;->OooO0OO:Llyiahf/vczjk/qs5;

    check-cast v1, Llyiahf/vczjk/fw8;

    invoke-virtual {v1}, Llyiahf/vczjk/fw8;->getValue()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/f62;

    if-eqz v1, :cond_0

    sget v0, Llyiahf/vczjk/yx5;->OooO00o:F

    invoke-interface {v1, v0}, Llyiahf/vczjk/f62;->Ooooo00(F)F

    move-result v0

    invoke-static {v0}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    move-result-object v0

    return-object v0

    :cond_0
    new-instance v1, Ljava/lang/StringBuilder;

    const-string v2, "The density on DrawerState ("

    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string v0, ") was not set. Did you use DrawerState with the ModalNavigationDrawer or DismissibleNavigationDrawer composables?"

    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    new-instance v1, Ljava/lang/IllegalArgumentException;

    invoke-virtual {v0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    move-result-object v0

    invoke-direct {v1, v0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw v1

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
