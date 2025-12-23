.class public final Llyiahf/vczjk/uv2;
.super Llyiahf/vczjk/hk4;
.source "SourceFile"


# static fields
.field public static final OooO0o:Llyiahf/vczjk/uv2;


# direct methods
.method static constructor <clinit>()V
    .locals 3

    new-instance v0, Llyiahf/vczjk/uv2;

    new-instance v1, Llyiahf/vczjk/q45;

    const-string v2, "FallbackBuiltIns"

    invoke-direct {v1, v2}, Llyiahf/vczjk/q45;-><init>(Ljava/lang/String;)V

    invoke-direct {v0, v1}, Llyiahf/vczjk/hk4;-><init>(Llyiahf/vczjk/q45;)V

    invoke-virtual {v0}, Llyiahf/vczjk/hk4;->OooO0OO()V

    sput-object v0, Llyiahf/vczjk/uv2;->OooO0o:Llyiahf/vczjk/uv2;

    return-void
.end method


# virtual methods
.method public final bridge synthetic OooOOo0()Llyiahf/vczjk/cx6;
    .locals 1

    sget-object v0, Llyiahf/vczjk/tp3;->OooOOoo:Llyiahf/vczjk/tp3;

    return-object v0
.end method
