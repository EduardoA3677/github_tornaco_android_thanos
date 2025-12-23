.class public final synthetic Llyiahf/vczjk/n44;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/le3;


# instance fields
.field public final synthetic OooOOO:Llyiahf/vczjk/q44;

.field public final synthetic OooOOO0:I


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/q44;I)V
    .locals 0

    iput p2, p0, Llyiahf/vczjk/n44;->OooOOO0:I

    iput-object p1, p0, Llyiahf/vczjk/n44;->OooOOO:Llyiahf/vczjk/q44;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final OooO00o()Ljava/lang/Object;
    .locals 2

    iget v0, p0, Llyiahf/vczjk/n44;->OooOOO0:I

    packed-switch v0, :pswitch_data_0

    iget-object v0, p0, Llyiahf/vczjk/n44;->OooOOO:Llyiahf/vczjk/q44;

    iget-object v1, v0, Llyiahf/vczjk/q44;->OooO00o:Llyiahf/vczjk/ru7;

    invoke-virtual {v1}, Llyiahf/vczjk/ru7;->inCompatibilityMode$room_runtime_release()Z

    move-result v1

    if-eqz v1, :cond_1

    iget-object v0, v0, Llyiahf/vczjk/q44;->OooO00o:Llyiahf/vczjk/ru7;

    invoke-virtual {v0}, Llyiahf/vczjk/ru7;->isOpenInternal()Z

    move-result v0

    if-eqz v0, :cond_0

    goto :goto_0

    :cond_0
    const/4 v0, 0x0

    goto :goto_1

    :cond_1
    :goto_0
    const/4 v0, 0x1

    :goto_1
    invoke-static {v0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    move-result-object v0

    return-object v0

    :pswitch_0
    iget-object v0, p0, Llyiahf/vczjk/n44;->OooOOO:Llyiahf/vczjk/q44;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v0

    :pswitch_1
    iget-object v0, p0, Llyiahf/vczjk/n44;->OooOOO:Llyiahf/vczjk/q44;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v0

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
