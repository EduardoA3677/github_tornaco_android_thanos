.class public final Llyiahf/vczjk/za5;
.super Llyiahf/vczjk/g26;
.source "SourceFile"


# static fields
.field public static final OooO:Llyiahf/vczjk/h93;


# instance fields
.field public OooO00o:Ljava/util/ArrayList;

.field public OooO0O0:Ljava/util/HashMap;

.field public OooO0OO:Ljava/util/ArrayList;

.field public OooO0Oo:Ljava/util/HashMap;

.field public OooO0o:Ljava/util/ArrayList;

.field public OooO0o0:Ljava/util/ArrayList;

.field public OooO0oO:Llyiahf/vczjk/s69;

.field public final synthetic OooO0oo:Llyiahf/vczjk/rr0;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    new-instance v0, Llyiahf/vczjk/h93;

    const/16 v1, 0x1d

    invoke-direct {v0, v1}, Llyiahf/vczjk/h93;-><init>(I)V

    sput-object v0, Llyiahf/vczjk/za5;->OooO:Llyiahf/vczjk/h93;

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/rr0;)V
    .locals 1

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/za5;->OooO0oo:Llyiahf/vczjk/rr0;

    new-instance p1, Ljava/util/ArrayList;

    const/4 v0, 0x3

    invoke-direct {p1, v0}, Ljava/util/ArrayList;-><init>(I)V

    iput-object p1, p0, Llyiahf/vczjk/za5;->OooO00o:Ljava/util/ArrayList;

    new-instance p1, Ljava/util/HashMap;

    invoke-direct {p1}, Ljava/util/HashMap;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/za5;->OooO0O0:Ljava/util/HashMap;

    new-instance p1, Ljava/util/ArrayList;

    invoke-direct {p1}, Ljava/util/ArrayList;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/za5;->OooO0OO:Ljava/util/ArrayList;

    new-instance p1, Ljava/util/HashMap;

    invoke-direct {p1}, Ljava/util/HashMap;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/za5;->OooO0Oo:Ljava/util/HashMap;

    new-instance p1, Ljava/util/ArrayList;

    invoke-direct {p1}, Ljava/util/ArrayList;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/za5;->OooO0o0:Ljava/util/ArrayList;

    new-instance p1, Ljava/util/ArrayList;

    invoke-direct {p1}, Ljava/util/ArrayList;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/za5;->OooO0o:Ljava/util/ArrayList;

    new-instance p1, Llyiahf/vczjk/s69;

    invoke-direct {p1}, Llyiahf/vczjk/s69;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/za5;->OooO0oO:Llyiahf/vczjk/s69;

    return-void
.end method


# virtual methods
.method public final OooO0O0(Ljava/lang/String;Ljava/lang/String;)Llyiahf/vczjk/g26;
    .locals 1

    new-instance v0, Llyiahf/vczjk/ya5;

    invoke-direct {v0, p0, p1, p2}, Llyiahf/vczjk/ya5;-><init>(Llyiahf/vczjk/za5;Ljava/lang/String;Ljava/lang/String;)V

    iget-object p1, p0, Llyiahf/vczjk/za5;->OooO00o:Ljava/util/ArrayList;

    invoke-virtual {p1, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    return-object v0
.end method

.method public final OooO0OO()V
    .locals 0

    return-void
.end method

.method public final OooO0o(Llyiahf/vczjk/r69;)Llyiahf/vczjk/r69;
    .locals 1

    if-nez p1, :cond_0

    const/4 p1, 0x0

    return-object p1

    :cond_0
    iget-object v0, p0, Llyiahf/vczjk/za5;->OooO0OO:Ljava/util/ArrayList;

    invoke-virtual {v0, p1}, Ljava/util/ArrayList;->indexOf(Ljava/lang/Object;)I

    move-result v0

    if-gez v0, :cond_1

    new-instance v0, Llyiahf/vczjk/r69;

    iget-object p1, p1, Llyiahf/vczjk/r69;->OooO00o:Ljava/lang/String;

    invoke-direct {v0, p1}, Llyiahf/vczjk/r69;-><init>(Ljava/lang/String;)V

    iget-object p1, p0, Llyiahf/vczjk/za5;->OooO0OO:Ljava/util/ArrayList;

    invoke-virtual {p1, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    return-object v0

    :cond_1
    iget-object p1, p0, Llyiahf/vczjk/za5;->OooO0OO:Ljava/util/ArrayList;

    invoke-virtual {p1, v0}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/r69;

    return-object p1
.end method
