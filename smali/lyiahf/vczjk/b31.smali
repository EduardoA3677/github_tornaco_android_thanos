.class public abstract Llyiahf/vczjk/b31;
.super Ljava/lang/Object;
.source "SourceFile"


# static fields
.field public static final OooO00o:Llyiahf/vczjk/sp3;


# direct methods
.method static constructor <clinit>()V
    .locals 3

    new-instance v0, Llyiahf/vczjk/sp3;

    const/high16 v1, 0x3f800000    # 1.0f

    const-string v2, "alpha"

    invoke-direct {v0, v1, v2}, Llyiahf/vczjk/sp3;-><init>(FLjava/lang/String;)V

    sput-object v0, Llyiahf/vczjk/b31;->OooO00o:Llyiahf/vczjk/sp3;

    return-void
.end method

.method public static final OooO00o(Ljava/lang/String;)Llyiahf/vczjk/y05;
    .locals 5

    invoke-static {}, Llyiahf/vczjk/r02;->OooOOO0()Llyiahf/vczjk/y05;

    move-result-object v0

    const/4 v1, 0x0

    :goto_0
    invoke-virtual {p0}, Ljava/lang/String;->length()I

    move-result v2

    if-ge v1, v2, :cond_0

    invoke-virtual {p0, v1}, Ljava/lang/String;->charAt(I)C

    move-result v2

    new-instance v3, Llyiahf/vczjk/sp3;

    invoke-static {v2}, Ljava/lang/String;->valueOf(C)Ljava/lang/String;

    move-result-object v2

    const/high16 v4, 0x3f800000    # 1.0f

    invoke-direct {v3, v4, v2}, Llyiahf/vczjk/sp3;-><init>(FLjava/lang/String;)V

    invoke-virtual {v0, v3}, Llyiahf/vczjk/y05;->add(Ljava/lang/Object;)Z

    add-int/lit8 v1, v1, 0x1

    goto :goto_0

    :cond_0
    sget-object p0, Llyiahf/vczjk/b31;->OooO00o:Llyiahf/vczjk/sp3;

    invoke-virtual {v0, p0}, Llyiahf/vczjk/y05;->add(Ljava/lang/Object;)Z

    invoke-virtual {v0}, Llyiahf/vczjk/y05;->OooOOO0()Llyiahf/vczjk/y05;

    move-result-object p0

    return-object p0
.end method
