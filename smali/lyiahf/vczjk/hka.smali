.class public abstract Llyiahf/vczjk/hka;
.super Ljava/lang/Object;
.source "SourceFile"


# static fields
.field public static final OooO00o:Ljava/lang/Object;


# direct methods
.method static constructor <clinit>()V
    .locals 12

    const/high16 v0, 0x3f000000    # 0.5f

    invoke-static {v0}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    move-result-object v0

    sget-object v1, Llyiahf/vczjk/gda;->OooO0O0:Llyiahf/vczjk/n1a;

    const/high16 v2, 0x3f800000    # 1.0f

    invoke-static {v2}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    move-result-object v2

    new-instance v3, Llyiahf/vczjk/xn6;

    invoke-direct {v3, v1, v2}, Llyiahf/vczjk/xn6;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    sget-object v1, Llyiahf/vczjk/gda;->OooO0oo:Llyiahf/vczjk/n1a;

    new-instance v4, Llyiahf/vczjk/xn6;

    invoke-direct {v4, v1, v2}, Llyiahf/vczjk/xn6;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    sget-object v1, Llyiahf/vczjk/gda;->OooO0oO:Llyiahf/vczjk/n1a;

    new-instance v5, Llyiahf/vczjk/xn6;

    invoke-direct {v5, v1, v2}, Llyiahf/vczjk/xn6;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    sget-object v1, Llyiahf/vczjk/gda;->OooO00o:Llyiahf/vczjk/n1a;

    const v2, 0x3c23d70a    # 0.01f

    invoke-static {v2}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    move-result-object v2

    new-instance v6, Llyiahf/vczjk/xn6;

    invoke-direct {v6, v1, v2}, Llyiahf/vczjk/xn6;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    sget-object v1, Llyiahf/vczjk/gda;->OooO:Llyiahf/vczjk/n1a;

    new-instance v7, Llyiahf/vczjk/xn6;

    invoke-direct {v7, v1, v0}, Llyiahf/vczjk/xn6;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    sget-object v1, Llyiahf/vczjk/gda;->OooO0o0:Llyiahf/vczjk/n1a;

    new-instance v8, Llyiahf/vczjk/xn6;

    invoke-direct {v8, v1, v0}, Llyiahf/vczjk/xn6;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    sget-object v1, Llyiahf/vczjk/gda;->OooO0o:Llyiahf/vczjk/n1a;

    new-instance v9, Llyiahf/vczjk/xn6;

    invoke-direct {v9, v1, v0}, Llyiahf/vczjk/xn6;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    sget-object v0, Llyiahf/vczjk/gda;->OooO0OO:Llyiahf/vczjk/n1a;

    const v1, 0x3dcccccd    # 0.1f

    invoke-static {v1}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    move-result-object v2

    new-instance v10, Llyiahf/vczjk/xn6;

    invoke-direct {v10, v0, v2}, Llyiahf/vczjk/xn6;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    sget-object v0, Llyiahf/vczjk/gda;->OooO0Oo:Llyiahf/vczjk/n1a;

    invoke-static {v1}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    move-result-object v1

    new-instance v11, Llyiahf/vczjk/xn6;

    invoke-direct {v11, v0, v1}, Llyiahf/vczjk/xn6;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    filled-new-array/range {v3 .. v11}, [Llyiahf/vczjk/xn6;

    move-result-object v0

    invoke-static {v0}, Llyiahf/vczjk/lc5;->o0ooOO0([Llyiahf/vczjk/xn6;)Ljava/util/Map;

    move-result-object v0

    sput-object v0, Llyiahf/vczjk/hka;->OooO00o:Ljava/lang/Object;

    return-void
.end method
