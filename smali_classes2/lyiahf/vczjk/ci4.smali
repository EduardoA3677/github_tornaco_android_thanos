.class public final Llyiahf/vczjk/ci4;
.super Ljava/lang/Object;

# interfaces
.implements Llyiahf/vczjk/le3;


# instance fields
.field public final OooOOO:Llyiahf/vczjk/di4;

.field public final synthetic OooOOO0:I


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/di4;I)V
    .locals 0

    iput p2, p0, Llyiahf/vczjk/ci4;->OooOOO0:I

    iput-object p1, p0, Llyiahf/vczjk/ci4;->OooOOO:Llyiahf/vczjk/di4;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final OooO00o()Ljava/lang/Object;
    .locals 2

    iget v0, p0, Llyiahf/vczjk/ci4;->OooOOO0:I

    packed-switch v0, :pswitch_data_0

    iget-object v0, p0, Llyiahf/vczjk/ci4;->OooOOO:Llyiahf/vczjk/di4;

    iget-object v0, v0, Llyiahf/vczjk/di4;->OooO0O0:Llyiahf/vczjk/wm7;

    if-eqz v0, :cond_0

    invoke-virtual {v0}, Llyiahf/vczjk/wm7;->OooO00o()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Ljava/lang/reflect/Type;

    goto :goto_0

    :cond_0
    const/4 v0, 0x0

    :goto_0
    invoke-static {v0}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    invoke-static {v0}, Llyiahf/vczjk/rl7;->OooO0OO(Ljava/lang/reflect/Type;)Ljava/util/List;

    move-result-object v0

    return-object v0

    :pswitch_0
    iget-object v0, p0, Llyiahf/vczjk/ci4;->OooOOO:Llyiahf/vczjk/di4;

    iget-object v1, v0, Llyiahf/vczjk/di4;->OooO00o:Llyiahf/vczjk/uk4;

    invoke-virtual {v0, v1}, Llyiahf/vczjk/di4;->OooO00o(Llyiahf/vczjk/uk4;)Llyiahf/vczjk/tf4;

    move-result-object v0

    return-object v0

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
