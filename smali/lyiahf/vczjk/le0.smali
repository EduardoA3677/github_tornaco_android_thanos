.class public final Llyiahf/vczjk/le0;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field final synthetic $brush:Llyiahf/vczjk/ri0;

.field final synthetic $rectTopLeft:J

.field final synthetic $size:J

.field final synthetic $style:Llyiahf/vczjk/ig2;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/gx8;JJLlyiahf/vczjk/ig2;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/le0;->$brush:Llyiahf/vczjk/ri0;

    iput-wide p2, p0, Llyiahf/vczjk/le0;->$rectTopLeft:J

    iput-wide p4, p0, Llyiahf/vczjk/le0;->$size:J

    iput-object p6, p0, Llyiahf/vczjk/le0;->$style:Llyiahf/vczjk/ig2;

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 9

    check-cast p1, Llyiahf/vczjk/mm1;

    move-object v0, p1

    check-cast v0, Llyiahf/vczjk/to4;

    invoke-virtual {v0}, Llyiahf/vczjk/to4;->OooO00o()V

    iget-object v1, p0, Llyiahf/vczjk/le0;->$brush:Llyiahf/vczjk/ri0;

    iget-wide v2, p0, Llyiahf/vczjk/le0;->$rectTopLeft:J

    iget-wide v4, p0, Llyiahf/vczjk/le0;->$size:J

    iget-object v7, p0, Llyiahf/vczjk/le0;->$style:Llyiahf/vczjk/ig2;

    const/4 v6, 0x0

    const/16 v8, 0x68

    invoke-static/range {v0 .. v8}, Llyiahf/vczjk/hg2;->OooO0oo(Llyiahf/vczjk/hg2;Llyiahf/vczjk/ri0;JJFLlyiahf/vczjk/ig2;I)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
