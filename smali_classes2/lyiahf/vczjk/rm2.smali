.class public final Llyiahf/vczjk/rm2;
.super Llyiahf/vczjk/gy;
.source "SourceFile"


# static fields
.field public static final OooOOO0:Llyiahf/vczjk/rm2;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    new-instance v0, Llyiahf/vczjk/rm2;

    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    sput-object v0, Llyiahf/vczjk/rm2;->OooOOO0:Llyiahf/vczjk/rm2;

    return-void
.end method


# virtual methods
.method public final OooO00o()I
    .locals 1

    const/4 v0, 0x0

    return v0
.end method

.method public final OooO0O0(ILlyiahf/vczjk/qo;)V
    .locals 0

    check-cast p2, Ljava/lang/Void;

    new-instance p1, Ljava/lang/IllegalStateException;

    invoke-direct {p1}, Ljava/lang/IllegalStateException;-><init>()V

    throw p1
.end method

.method public final bridge synthetic get(I)Ljava/lang/Object;
    .locals 0

    const/4 p1, 0x0

    return-object p1
.end method

.method public final iterator()Ljava/util/Iterator;
    .locals 1

    new-instance v0, Llyiahf/vczjk/qm2;

    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    return-object v0
.end method
