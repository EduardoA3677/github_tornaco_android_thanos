.class public final Llyiahf/vczjk/nx0;
.super Landroid/util/Property;
.source "SourceFile"


# static fields
.field public static final OooO00o:Llyiahf/vczjk/nx0;


# direct methods
.method static constructor <clinit>()V
    .locals 3

    new-instance v0, Llyiahf/vczjk/nx0;

    const-class v1, Llyiahf/vczjk/px0;

    const-string v2, "circularReveal"

    invoke-direct {v0, v1, v2}, Landroid/util/Property;-><init>(Ljava/lang/Class;Ljava/lang/String;)V

    sput-object v0, Llyiahf/vczjk/nx0;->OooO00o:Llyiahf/vczjk/nx0;

    return-void
.end method


# virtual methods
.method public final get(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/qx0;

    invoke-interface {p1}, Llyiahf/vczjk/qx0;->getRevealInfo()Llyiahf/vczjk/px0;

    move-result-object p1

    return-object p1
.end method

.method public final set(Ljava/lang/Object;Ljava/lang/Object;)V
    .locals 0

    check-cast p1, Llyiahf/vczjk/qx0;

    check-cast p2, Llyiahf/vczjk/px0;

    invoke-interface {p1, p2}, Llyiahf/vczjk/qx0;->setRevealInfo(Llyiahf/vczjk/px0;)V

    return-void
.end method
