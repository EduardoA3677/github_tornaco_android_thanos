.class public final Llyiahf/vczjk/oO000Oo0;
.super Lutil/Singleton2;
.source "SourceFile"


# instance fields
.field public final synthetic OooO00o:I


# direct methods
.method public synthetic constructor <init>(I)V
    .locals 0

    iput p1, p0, Llyiahf/vczjk/oO000Oo0;->OooO00o:I

    invoke-direct {p0}, Lutil/Singleton2;-><init>()V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 2

    iget v0, p0, Llyiahf/vczjk/oO000Oo0;->OooO00o:I

    packed-switch v0, :pswitch_data_0

    check-cast p1, Landroid/content/Context;

    new-instance v0, Llyiahf/vczjk/xh3;

    invoke-direct {v0, p1}, Llyiahf/vczjk/xh3;-><init>(Landroid/content/Context;)V

    return-object v0

    :pswitch_0
    check-cast p1, Landroid/content/Context;

    const-class v0, Lnow/fortuitous/app/donate/data/local/ActivationDatabase;

    const-string v1, "activation.db"

    invoke-static {p1, v0, v1}, Llyiahf/vczjk/rd3;->OooOOOo(Landroid/content/Context;Ljava/lang/Class;Ljava/lang/String;)Llyiahf/vczjk/lu7;

    move-result-object p1

    const/4 v0, 0x1

    iput-boolean v0, p1, Llyiahf/vczjk/lu7;->OooO:Z

    invoke-virtual {p1}, Llyiahf/vczjk/lu7;->OooO0O0()Llyiahf/vczjk/ru7;

    move-result-object p1

    check-cast p1, Lnow/fortuitous/app/donate/data/local/ActivationDatabase;

    return-object p1

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
