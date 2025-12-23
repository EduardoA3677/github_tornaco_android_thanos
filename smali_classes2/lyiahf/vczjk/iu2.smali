.class public final Llyiahf/vczjk/iu2;
.super Ljava/lang/Object;
.source "SourceFile"


# static fields
.field public static final synthetic OooO0O0:I


# instance fields
.field public final OooO00o:Ljava/util/Map;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    new-instance v0, Llyiahf/vczjk/iu2;

    const/4 v1, 0x0

    invoke-direct {v0, v1}, Llyiahf/vczjk/iu2;-><init>(I)V

    return-void
.end method

.method public constructor <init>()V
    .locals 1

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    new-instance v0, Ljava/util/HashMap;

    invoke-direct {v0}, Ljava/util/HashMap;-><init>()V

    iput-object v0, p0, Llyiahf/vczjk/iu2;->OooO00o:Ljava/util/Map;

    return-void
.end method

.method public constructor <init>(I)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    sget-object p1, Ljava/util/Collections;->EMPTY_MAP:Ljava/util/Map;

    iput-object p1, p0, Llyiahf/vczjk/iu2;->OooO00o:Ljava/util/Map;

    return-void
.end method


# virtual methods
.method public final OooO00o(Llyiahf/vczjk/ug3;)V
    .locals 3

    new-instance v0, Llyiahf/vczjk/hu2;

    iget-object v1, p1, Llyiahf/vczjk/ug3;->OooO00o:Llyiahf/vczjk/sg3;

    iget-object v2, p1, Llyiahf/vczjk/ug3;->OooO0Oo:Llyiahf/vczjk/tg3;

    iget v2, v2, Llyiahf/vczjk/tg3;->OooOOO0:I

    invoke-direct {v0, v2, v1}, Llyiahf/vczjk/hu2;-><init>(ILlyiahf/vczjk/pi5;)V

    iget-object v1, p0, Llyiahf/vczjk/iu2;->OooO00o:Ljava/util/Map;

    invoke-interface {v1, v0, p1}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    return-void
.end method
