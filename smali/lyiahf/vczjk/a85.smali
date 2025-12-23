.class public final Llyiahf/vczjk/a85;
.super Ljava/lang/Object;
.source "SourceFile"


# static fields
.field public static final OooO0O0:Llyiahf/vczjk/a85;


# instance fields
.field public final OooO00o:Llyiahf/vczjk/i95;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    new-instance v0, Llyiahf/vczjk/a85;

    invoke-direct {v0}, Llyiahf/vczjk/a85;-><init>()V

    sput-object v0, Llyiahf/vczjk/a85;->OooO0O0:Llyiahf/vczjk/a85;

    return-void
.end method

.method public constructor <init>()V
    .locals 2

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    new-instance v0, Llyiahf/vczjk/i95;

    const/16 v1, 0x14

    invoke-direct {v0, v1}, Llyiahf/vczjk/i95;-><init>(I)V

    iput-object v0, p0, Llyiahf/vczjk/a85;->OooO00o:Llyiahf/vczjk/i95;

    return-void
.end method


# virtual methods
.method public final OooO00o(Ljava/lang/String;)Llyiahf/vczjk/z75;
    .locals 1

    if-nez p1, :cond_0

    const/4 p1, 0x0

    return-object p1

    :cond_0
    iget-object v0, p0, Llyiahf/vczjk/a85;->OooO00o:Llyiahf/vczjk/i95;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/i95;->OooO0O0(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/z75;

    return-object p1
.end method
