.class public final Llyiahf/vczjk/k3a;
.super Llyiahf/vczjk/wr6;
.source "SourceFile"


# static fields
.field public static final OooO:Llyiahf/vczjk/k3a;

.field public static final OooO0oo:Llyiahf/vczjk/k3a;

.field public static final OooOO0:Llyiahf/vczjk/k3a;


# instance fields
.field public final synthetic OooO0oO:I


# direct methods
.method static synthetic constructor <clinit>()V
    .locals 2

    new-instance v0, Llyiahf/vczjk/k3a;

    const/4 v1, 0x0

    invoke-direct {v0, v1}, Llyiahf/vczjk/k3a;-><init>(I)V

    sput-object v0, Llyiahf/vczjk/k3a;->OooO0oo:Llyiahf/vczjk/k3a;

    new-instance v0, Llyiahf/vczjk/k3a;

    const/4 v1, 0x1

    invoke-direct {v0, v1}, Llyiahf/vczjk/k3a;-><init>(I)V

    sput-object v0, Llyiahf/vczjk/k3a;->OooO:Llyiahf/vczjk/k3a;

    new-instance v0, Llyiahf/vczjk/k3a;

    const/4 v1, 0x2

    invoke-direct {v0, v1}, Llyiahf/vczjk/k3a;-><init>(I)V

    sput-object v0, Llyiahf/vczjk/k3a;->OooOO0:Llyiahf/vczjk/k3a;

    return-void
.end method

.method public synthetic constructor <init>(I)V
    .locals 0

    iput p1, p0, Llyiahf/vczjk/k3a;->OooO0oO:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final OooOo(Llyiahf/vczjk/l3a;Llyiahf/vczjk/yk4;)Llyiahf/vczjk/pt7;
    .locals 1

    iget v0, p0, Llyiahf/vczjk/k3a;->OooO0oO:I

    packed-switch v0, :pswitch_data_0

    const-string v0, "state"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "type"

    invoke-static {p2, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object p1, p1, Llyiahf/vczjk/l3a;->OooO0OO:Llyiahf/vczjk/fz0;

    invoke-interface {p1, p2}, Llyiahf/vczjk/fz0;->OooO0oO(Llyiahf/vczjk/yk4;)Llyiahf/vczjk/dp8;

    move-result-object p1

    return-object p1

    :pswitch_0
    const-string v0, "state"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string p1, "type"

    invoke-static {p2, p1}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance p1, Ljava/lang/UnsupportedOperationException;

    const-string p2, "Should not be called"

    invoke-direct {p1, p2}, Ljava/lang/UnsupportedOperationException;-><init>(Ljava/lang/String;)V

    throw p1

    :pswitch_1
    const-string v0, "state"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "type"

    invoke-static {p2, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object p1, p1, Llyiahf/vczjk/l3a;->OooO0OO:Llyiahf/vczjk/fz0;

    invoke-interface {p1, p2}, Llyiahf/vczjk/fz0;->o00Ooo(Llyiahf/vczjk/yk4;)Llyiahf/vczjk/dp8;

    move-result-object p1

    return-object p1

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
