.class public final Llyiahf/vczjk/lg;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/le3;


# instance fields
.field final synthetic $brush:Llyiahf/vczjk/ri0;

.field final synthetic $size:J


# direct methods
.method public constructor <init>(Llyiahf/vczjk/ri0;J)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/lg;->$brush:Llyiahf/vczjk/ri0;

    iput-wide p2, p0, Llyiahf/vczjk/lg;->$size:J

    const/4 p1, 0x0

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO00o()Ljava/lang/Object;
    .locals 3

    iget-object v0, p0, Llyiahf/vczjk/lg;->$brush:Llyiahf/vczjk/ri0;

    check-cast v0, Llyiahf/vczjk/fj8;

    iget-wide v1, p0, Llyiahf/vczjk/lg;->$size:J

    invoke-virtual {v0, v1, v2}, Llyiahf/vczjk/fj8;->OooO0O0(J)Landroid/graphics/Shader;

    move-result-object v0

    return-object v0
.end method
