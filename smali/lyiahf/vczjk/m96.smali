.class public final Llyiahf/vczjk/m96;
.super Ljava/lang/Object;
.source "SourceFile"


# static fields
.field public static final OooO0o:Ljava/util/LinkedHashSet;

.field public static final OooO0oO:Llyiahf/vczjk/tp3;


# instance fields
.field public final OooO00o:Llyiahf/vczjk/we4;

.field public final OooO0O0:Llyiahf/vczjk/j96;

.field public final OooO0OO:Llyiahf/vczjk/ze3;

.field public final OooO0Oo:Llyiahf/vczjk/rm4;

.field public final OooO0o0:Llyiahf/vczjk/sc9;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    new-instance v0, Ljava/util/LinkedHashSet;

    invoke-direct {v0}, Ljava/util/LinkedHashSet;-><init>()V

    sput-object v0, Llyiahf/vczjk/m96;->OooO0o:Ljava/util/LinkedHashSet;

    new-instance v0, Llyiahf/vczjk/tp3;

    const/16 v1, 0x19

    invoke-direct {v0, v1}, Llyiahf/vczjk/tp3;-><init>(I)V

    sput-object v0, Llyiahf/vczjk/m96;->OooO0oO:Llyiahf/vczjk/tp3;

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/we4;Llyiahf/vczjk/j96;Llyiahf/vczjk/le3;)V
    .locals 2

    sget-object v0, Llyiahf/vczjk/ye1;->OooOoO0:Llyiahf/vczjk/ye1;

    const-string v1, "fileSystem"

    invoke-static {p1, v1}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/m96;->OooO00o:Llyiahf/vczjk/we4;

    iput-object p2, p0, Llyiahf/vczjk/m96;->OooO0O0:Llyiahf/vczjk/j96;

    iput-object v0, p0, Llyiahf/vczjk/m96;->OooO0OO:Llyiahf/vczjk/ze3;

    check-cast p3, Llyiahf/vczjk/rm4;

    iput-object p3, p0, Llyiahf/vczjk/m96;->OooO0Oo:Llyiahf/vczjk/rm4;

    new-instance p1, Llyiahf/vczjk/k96;

    invoke-direct {p1, p0}, Llyiahf/vczjk/k96;-><init>(Llyiahf/vczjk/m96;)V

    invoke-static {p1}, Llyiahf/vczjk/jp8;->Oooo0(Llyiahf/vczjk/le3;)Llyiahf/vczjk/sc9;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/m96;->OooO0o0:Llyiahf/vczjk/sc9;

    return-void
.end method
