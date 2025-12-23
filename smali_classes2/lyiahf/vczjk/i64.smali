.class public final Llyiahf/vczjk/i64;
.super Llyiahf/vczjk/z54;
.source "SourceFile"


# static fields
.field public static final synthetic OooO0oO:[Llyiahf/vczjk/th4;


# instance fields
.field public final OooO0o:Llyiahf/vczjk/o45;


# direct methods
.method static constructor <clinit>()V
    .locals 5

    new-instance v0, Llyiahf/vczjk/za7;

    const-class v1, Llyiahf/vczjk/i64;

    const-string v2, "allValueArguments"

    const-string v3, "getAllValueArguments()Ljava/util/Map;"

    const/4 v4, 0x0

    invoke-direct {v0, v1, v2, v3, v4}, Llyiahf/vczjk/za7;-><init>(Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;I)V

    sget-object v1, Llyiahf/vczjk/ym7;->OooO00o:Llyiahf/vczjk/zm7;

    invoke-virtual {v1, v0}, Llyiahf/vczjk/zm7;->OooO0oO(Llyiahf/vczjk/za7;)Llyiahf/vczjk/mh4;

    move-result-object v0

    const/4 v1, 0x1

    new-array v1, v1, [Llyiahf/vczjk/th4;

    aput-object v0, v1, v4

    sput-object v1, Llyiahf/vczjk/i64;->OooO0oO:[Llyiahf/vczjk/th4;

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/sl7;Llyiahf/vczjk/ld9;)V
    .locals 1

    const-string v0, "c"

    invoke-static {p2, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    sget-object v0, Llyiahf/vczjk/w09;->OooOOO0:Llyiahf/vczjk/hc3;

    invoke-direct {p0, p2, p1, v0}, Llyiahf/vczjk/z54;-><init>(Llyiahf/vczjk/ld9;Llyiahf/vczjk/sl7;Llyiahf/vczjk/hc3;)V

    iget-object p1, p2, Llyiahf/vczjk/ld9;->OooOOO:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/s64;

    iget-object p1, p1, Llyiahf/vczjk/s64;->OooO00o:Llyiahf/vczjk/q45;

    sget-object p2, Llyiahf/vczjk/dk0;->OooOo0:Llyiahf/vczjk/dk0;

    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    new-instance v0, Llyiahf/vczjk/o45;

    invoke-direct {v0, p1, p2}, Llyiahf/vczjk/n45;-><init>(Llyiahf/vczjk/q45;Llyiahf/vczjk/le3;)V

    iput-object v0, p0, Llyiahf/vczjk/i64;->OooO0o:Llyiahf/vczjk/o45;

    return-void
.end method


# virtual methods
.method public final OooO()Ljava/util/Map;
    .locals 3

    iget-object v0, p0, Llyiahf/vczjk/i64;->OooO0o:Llyiahf/vczjk/o45;

    sget-object v1, Llyiahf/vczjk/i64;->OooO0oO:[Llyiahf/vczjk/th4;

    const/4 v2, 0x0

    aget-object v1, v1, v2

    invoke-static {v0, v1}, Llyiahf/vczjk/xr6;->OooOO0o(Llyiahf/vczjk/t26;Llyiahf/vczjk/th4;)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Ljava/util/Map;

    return-object v0
.end method
