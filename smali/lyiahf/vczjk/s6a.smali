.class public abstract Llyiahf/vczjk/s6a;
.super Ljava/lang/Object;
.source "SourceFile"


# static fields
.field public static final OooO00o:Llyiahf/vczjk/rn9;

.field public static final OooO0O0:Llyiahf/vczjk/l39;


# direct methods
.method static constructor <clinit>()V
    .locals 15

    new-instance v13, Llyiahf/vczjk/jz4;

    sget v0, Llyiahf/vczjk/gz4;->OooO0O0:F

    const/4 v1, 0x0

    invoke-direct {v13, v0, v1}, Llyiahf/vczjk/jz4;-><init>(FI)V

    sget-object v0, Llyiahf/vczjk/rn9;->OooO0Oo:Llyiahf/vczjk/rn9;

    sget-object v12, Llyiahf/vczjk/f32;->OooO00o:Llyiahf/vczjk/vx6;

    const-wide/16 v8, 0x0

    const-wide/16 v10, 0x0

    const-wide/16 v1, 0x0

    const-wide/16 v3, 0x0

    const/4 v5, 0x0

    const/4 v6, 0x0

    const/4 v7, 0x0

    const v14, 0xe7ffff

    invoke-static/range {v0 .. v14}, Llyiahf/vczjk/rn9;->OooO00o(Llyiahf/vczjk/rn9;JJLlyiahf/vczjk/ib3;Llyiahf/vczjk/cb3;Llyiahf/vczjk/ba3;JJLlyiahf/vczjk/vx6;Llyiahf/vczjk/jz4;I)Llyiahf/vczjk/rn9;

    move-result-object v0

    sput-object v0, Llyiahf/vczjk/s6a;->OooO00o:Llyiahf/vczjk/rn9;

    sget-object v0, Llyiahf/vczjk/o24;->Oooo00o:Llyiahf/vczjk/o24;

    new-instance v1, Llyiahf/vczjk/l39;

    invoke-direct {v1, v0}, Landroidx/compose/runtime/OooO;-><init>(Llyiahf/vczjk/le3;)V

    sput-object v1, Llyiahf/vczjk/s6a;->OooO0O0:Llyiahf/vczjk/l39;

    return-void
.end method

.method public static final OooO00o(Llyiahf/vczjk/rn9;)Llyiahf/vczjk/rn9;
    .locals 15

    sget-object v7, Llyiahf/vczjk/ba3;->OooOOO0:Llyiahf/vczjk/g22;

    iget-object v0, p0, Llyiahf/vczjk/rn9;->OooO00o:Llyiahf/vczjk/dy8;

    iget-object v0, v0, Llyiahf/vczjk/dy8;->OooO0o:Llyiahf/vczjk/ba3;

    if-eqz v0, :cond_0

    return-object p0

    :cond_0
    const/4 v13, 0x0

    const v14, 0xffffdf

    const-wide/16 v1, 0x0

    const-wide/16 v3, 0x0

    const/4 v5, 0x0

    const/4 v6, 0x0

    const-wide/16 v8, 0x0

    const-wide/16 v10, 0x0

    const/4 v12, 0x0

    move-object v0, p0

    invoke-static/range {v0 .. v14}, Llyiahf/vczjk/rn9;->OooO00o(Llyiahf/vczjk/rn9;JJLlyiahf/vczjk/ib3;Llyiahf/vczjk/cb3;Llyiahf/vczjk/ba3;JJLlyiahf/vczjk/vx6;Llyiahf/vczjk/jz4;I)Llyiahf/vczjk/rn9;

    move-result-object p0

    return-object p0
.end method
