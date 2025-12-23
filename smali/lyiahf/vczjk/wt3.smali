.class public final Llyiahf/vczjk/wt3;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $$changed:I

.field final synthetic $$default:I

.field final synthetic $contentDescription:Ljava/lang/String;

.field final synthetic $modifier:Llyiahf/vczjk/kl5;

.field final synthetic $painter:Llyiahf/vczjk/un6;

.field final synthetic $tint:J


# direct methods
.method public constructor <init>(Llyiahf/vczjk/un6;Ljava/lang/String;Llyiahf/vczjk/kl5;JII)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/wt3;->$painter:Llyiahf/vczjk/un6;

    iput-object p2, p0, Llyiahf/vczjk/wt3;->$contentDescription:Ljava/lang/String;

    iput-object p3, p0, Llyiahf/vczjk/wt3;->$modifier:Llyiahf/vczjk/kl5;

    iput-wide p4, p0, Llyiahf/vczjk/wt3;->$tint:J

    iput p6, p0, Llyiahf/vczjk/wt3;->$$changed:I

    iput p7, p0, Llyiahf/vczjk/wt3;->$$default:I

    const/4 p1, 0x2

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 8

    move-object v5, p1

    check-cast v5, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Number;

    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    iget-object v0, p0, Llyiahf/vczjk/wt3;->$painter:Llyiahf/vczjk/un6;

    iget-object v1, p0, Llyiahf/vczjk/wt3;->$contentDescription:Ljava/lang/String;

    iget-object v2, p0, Llyiahf/vczjk/wt3;->$modifier:Llyiahf/vczjk/kl5;

    iget-wide v3, p0, Llyiahf/vczjk/wt3;->$tint:J

    iget p1, p0, Llyiahf/vczjk/wt3;->$$changed:I

    or-int/lit8 p1, p1, 0x1

    invoke-static {p1}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result v6

    iget v7, p0, Llyiahf/vczjk/wt3;->$$default:I

    invoke-static/range {v0 .. v7}, Llyiahf/vczjk/zt3;->OooO0O0(Llyiahf/vczjk/un6;Ljava/lang/String;Llyiahf/vczjk/kl5;JLlyiahf/vczjk/rf1;II)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
