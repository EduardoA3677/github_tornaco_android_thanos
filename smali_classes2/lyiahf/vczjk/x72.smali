.class public Llyiahf/vczjk/x72;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ko;


# static fields
.field public static final synthetic OooOOO:[Llyiahf/vczjk/th4;


# instance fields
.field public final OooOOO0:Llyiahf/vczjk/o45;


# direct methods
.method static constructor <clinit>()V
    .locals 5

    new-instance v0, Llyiahf/vczjk/za7;

    const-class v1, Llyiahf/vczjk/x72;

    const-string v2, "annotations"

    const-string v3, "getAnnotations()Ljava/util/List;"

    const/4 v4, 0x0

    invoke-direct {v0, v1, v2, v3, v4}, Llyiahf/vczjk/za7;-><init>(Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;I)V

    sget-object v1, Llyiahf/vczjk/ym7;->OooO00o:Llyiahf/vczjk/zm7;

    invoke-virtual {v1, v0}, Llyiahf/vczjk/zm7;->OooO0oO(Llyiahf/vczjk/za7;)Llyiahf/vczjk/mh4;

    move-result-object v0

    const/4 v1, 0x1

    new-array v1, v1, [Llyiahf/vczjk/th4;

    aput-object v0, v1, v4

    sput-object v1, Llyiahf/vczjk/x72;->OooOOO:[Llyiahf/vczjk/th4;

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/q45;Llyiahf/vczjk/le3;)V
    .locals 1

    const-string v0, "storageManager"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    new-instance v0, Llyiahf/vczjk/o45;

    invoke-direct {v0, p1, p2}, Llyiahf/vczjk/n45;-><init>(Llyiahf/vczjk/q45;Llyiahf/vczjk/le3;)V

    iput-object v0, p0, Llyiahf/vczjk/x72;->OooOOO0:Llyiahf/vczjk/o45;

    return-void
.end method


# virtual methods
.method public final OooO0o0(Llyiahf/vczjk/hc3;)Z
    .locals 0

    invoke-static {p0, p1}, Llyiahf/vczjk/mc4;->Oooo0oo(Llyiahf/vczjk/ko;Llyiahf/vczjk/hc3;)Z

    move-result p1

    return p1
.end method

.method public final OooO0oO(Llyiahf/vczjk/hc3;)Llyiahf/vczjk/un;
    .locals 0

    invoke-static {p0, p1}, Llyiahf/vczjk/mc4;->OooOoO(Llyiahf/vczjk/ko;Llyiahf/vczjk/hc3;)Llyiahf/vczjk/un;

    move-result-object p1

    return-object p1
.end method

.method public isEmpty()Z
    .locals 3

    iget-object v0, p0, Llyiahf/vczjk/x72;->OooOOO0:Llyiahf/vczjk/o45;

    sget-object v1, Llyiahf/vczjk/x72;->OooOOO:[Llyiahf/vczjk/th4;

    const/4 v2, 0x0

    aget-object v1, v1, v2

    invoke-static {v0, v1}, Llyiahf/vczjk/xr6;->OooOO0o(Llyiahf/vczjk/t26;Llyiahf/vczjk/th4;)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Ljava/util/List;

    invoke-interface {v0}, Ljava/util/List;->isEmpty()Z

    move-result v0

    return v0
.end method

.method public final iterator()Ljava/util/Iterator;
    .locals 3

    iget-object v0, p0, Llyiahf/vczjk/x72;->OooOOO0:Llyiahf/vczjk/o45;

    sget-object v1, Llyiahf/vczjk/x72;->OooOOO:[Llyiahf/vczjk/th4;

    const/4 v2, 0x0

    aget-object v1, v1, v2

    invoke-static {v0, v1}, Llyiahf/vczjk/xr6;->OooOO0o(Llyiahf/vczjk/t26;Llyiahf/vczjk/th4;)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Ljava/util/List;

    invoke-interface {v0}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    move-result-object v0

    return-object v0
.end method
