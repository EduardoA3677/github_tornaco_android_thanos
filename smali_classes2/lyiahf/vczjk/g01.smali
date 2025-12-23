.class public final Llyiahf/vczjk/g01;
.super Llyiahf/vczjk/kh3;
.source "SourceFile"


# static fields
.field public static final OooO0o0:Llyiahf/vczjk/qt5;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    const-string v0, "clone"

    invoke-static {v0}, Llyiahf/vczjk/qt5;->OooO0o0(Ljava/lang/String;)Llyiahf/vczjk/qt5;

    move-result-object v0

    sput-object v0, Llyiahf/vczjk/g01;->OooO0o0:Llyiahf/vczjk/qt5;

    return-void
.end method


# virtual methods
.method public final OooO0oo()Ljava/util/List;
    .locals 13

    sget-object v0, Llyiahf/vczjk/sx8;->OooOO0O:Llyiahf/vczjk/up3;

    iget-object v1, p0, Llyiahf/vczjk/kh3;->OooO0O0:Llyiahf/vczjk/oo0o0Oo;

    sget-object v2, Llyiahf/vczjk/g01;->OooO0o0:Llyiahf/vczjk/qt5;

    const/4 v3, 0x1

    invoke-static {v1, v2, v3, v0}, Llyiahf/vczjk/ho8;->o0000o0(Llyiahf/vczjk/by0;Llyiahf/vczjk/qt5;ILlyiahf/vczjk/sx8;)Llyiahf/vczjk/ho8;

    move-result-object v4

    invoke-virtual {v1}, Llyiahf/vczjk/oo0o0Oo;->o00000()Llyiahf/vczjk/mp4;

    move-result-object v6

    sget-object v7, Llyiahf/vczjk/an2;->OooOOO0:Llyiahf/vczjk/an2;

    invoke-static {v1}, Llyiahf/vczjk/p72;->OooO0o0(Llyiahf/vczjk/v02;)Llyiahf/vczjk/hk4;

    move-result-object v0

    invoke-virtual {v0}, Llyiahf/vczjk/hk4;->OooO0o0()Llyiahf/vczjk/dp8;

    move-result-object v10

    sget-object v11, Llyiahf/vczjk/yk5;->OooOOOo:Llyiahf/vczjk/yk5;

    sget-object v12, Llyiahf/vczjk/r72;->OooO0OO:Llyiahf/vczjk/q72;

    const/4 v5, 0x0

    move-object v8, v7

    move-object v9, v7

    invoke-virtual/range {v4 .. v12}, Llyiahf/vczjk/ho8;->o0000o0o(Llyiahf/vczjk/mp4;Llyiahf/vczjk/mp4;Ljava/util/List;Ljava/util/List;Ljava/util/List;Llyiahf/vczjk/uk4;Llyiahf/vczjk/yk5;Llyiahf/vczjk/q72;)Llyiahf/vczjk/ho8;

    invoke-static {v4}, Llyiahf/vczjk/r02;->OooOo(Ljava/lang/Object;)Ljava/util/List;

    move-result-object v0

    return-object v0
.end method
