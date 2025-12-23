.class public final synthetic Llyiahf/vczjk/j7a;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ol1;


# instance fields
.field public final synthetic OooO00o:I

.field public final synthetic OooO0O0:Llyiahf/vczjk/s77;


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/s77;I)V
    .locals 0

    iput p2, p0, Llyiahf/vczjk/j7a;->OooO00o:I

    iput-object p1, p0, Llyiahf/vczjk/j7a;->OooO0O0:Llyiahf/vczjk/s77;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final accept(Ljava/lang/Object;)V
    .locals 1

    iget v0, p0, Llyiahf/vczjk/j7a;->OooO00o:I

    packed-switch v0, :pswitch_data_0

    check-cast p1, Llyiahf/vczjk/voa;

    iget-object v0, p0, Llyiahf/vczjk/j7a;->OooO0O0:Llyiahf/vczjk/s77;

    check-cast v0, Llyiahf/vczjk/r77;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/r77;->OooO0oo(Ljava/lang/Object;)Ljava/lang/Object;

    return-void

    :pswitch_0
    check-cast p1, Llyiahf/vczjk/voa;

    iget-object v0, p0, Llyiahf/vczjk/j7a;->OooO0O0:Llyiahf/vczjk/s77;

    check-cast v0, Llyiahf/vczjk/r77;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/r77;->OooO0oo(Ljava/lang/Object;)Ljava/lang/Object;

    return-void

    :pswitch_1
    check-cast p1, Landroid/content/res/Configuration;

    iget-object v0, p0, Llyiahf/vczjk/j7a;->OooO0O0:Llyiahf/vczjk/s77;

    check-cast v0, Llyiahf/vczjk/r77;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-static {p1}, Llyiahf/vczjk/ll6;->OooOO0O(Landroid/content/res/Configuration;)Z

    move-result p1

    invoke-static {p1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    move-result-object p1

    invoke-virtual {v0, p1}, Llyiahf/vczjk/r77;->OooO0oo(Ljava/lang/Object;)Ljava/lang/Object;

    return-void

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
