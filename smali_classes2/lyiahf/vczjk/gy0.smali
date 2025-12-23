.class public final Llyiahf/vczjk/gy0;
.super Ljava/lang/Object;
.source "SourceFile"


# static fields
.field public static final OooO0OO:Ljava/util/Set;


# instance fields
.field public final OooO00o:Llyiahf/vczjk/s72;

.field public final OooO0O0:Llyiahf/vczjk/r60;


# direct methods
.method static constructor <clinit>()V
    .locals 3

    sget-object v0, Llyiahf/vczjk/w09;->OooO0OO:Llyiahf/vczjk/ic3;

    invoke-virtual {v0}, Llyiahf/vczjk/ic3;->OooO0oO()Llyiahf/vczjk/hc3;

    move-result-object v0

    new-instance v1, Llyiahf/vczjk/hy0;

    invoke-virtual {v0}, Llyiahf/vczjk/hc3;->OooO0O0()Llyiahf/vczjk/hc3;

    move-result-object v2

    iget-object v0, v0, Llyiahf/vczjk/hc3;->OooO00o:Llyiahf/vczjk/ic3;

    invoke-virtual {v0}, Llyiahf/vczjk/ic3;->OooO0o()Llyiahf/vczjk/qt5;

    move-result-object v0

    invoke-direct {v1, v2, v0}, Llyiahf/vczjk/hy0;-><init>(Llyiahf/vczjk/hc3;Llyiahf/vczjk/qt5;)V

    invoke-static {v1}, Llyiahf/vczjk/tp6;->Oooo0OO(Ljava/lang/Object;)Ljava/util/Set;

    move-result-object v0

    sput-object v0, Llyiahf/vczjk/gy0;->OooO0OO:Ljava/util/Set;

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/s72;)V
    .locals 2

    const-string v0, "components"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/gy0;->OooO00o:Llyiahf/vczjk/s72;

    new-instance v0, Llyiahf/vczjk/oo000o;

    const/16 v1, 0x8

    invoke-direct {v0, p0, v1}, Llyiahf/vczjk/oo000o;-><init>(Ljava/lang/Object;I)V

    iget-object p1, p1, Llyiahf/vczjk/s72;->OooO00o:Llyiahf/vczjk/q45;

    invoke-virtual {p1, v0}, Llyiahf/vczjk/q45;->OooO0OO(Llyiahf/vczjk/oe3;)Llyiahf/vczjk/r60;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/gy0;->OooO0O0:Llyiahf/vczjk/r60;

    return-void
.end method


# virtual methods
.method public final OooO00o(Llyiahf/vczjk/hy0;Llyiahf/vczjk/vx0;)Llyiahf/vczjk/by0;
    .locals 2

    const-string v0, "classId"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v0, p0, Llyiahf/vczjk/gy0;->OooO0O0:Llyiahf/vczjk/r60;

    new-instance v1, Llyiahf/vczjk/fy0;

    invoke-direct {v1, p1, p2}, Llyiahf/vczjk/fy0;-><init>(Llyiahf/vczjk/hy0;Llyiahf/vczjk/vx0;)V

    invoke-virtual {v0, v1}, Llyiahf/vczjk/r60;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/by0;

    return-object p1
.end method
