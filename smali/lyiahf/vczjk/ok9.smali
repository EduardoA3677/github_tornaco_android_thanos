.class public final Llyiahf/vczjk/ok9;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $$changed:I

.field final synthetic $direction:Llyiahf/vczjk/rr7;

.field final synthetic $isStartHandle:Z

.field final synthetic $manager:Llyiahf/vczjk/mk9;


# direct methods
.method public constructor <init>(ZLlyiahf/vczjk/rr7;Llyiahf/vczjk/mk9;I)V
    .locals 0

    iput-boolean p1, p0, Llyiahf/vczjk/ok9;->$isStartHandle:Z

    iput-object p2, p0, Llyiahf/vczjk/ok9;->$direction:Llyiahf/vczjk/rr7;

    iput-object p3, p0, Llyiahf/vczjk/ok9;->$manager:Llyiahf/vczjk/mk9;

    iput p4, p0, Llyiahf/vczjk/ok9;->$$changed:I

    const/4 p1, 0x2

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 3

    check-cast p1, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Number;

    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    iget-boolean p2, p0, Llyiahf/vczjk/ok9;->$isStartHandle:Z

    iget-object v0, p0, Llyiahf/vczjk/ok9;->$direction:Llyiahf/vczjk/rr7;

    iget-object v1, p0, Llyiahf/vczjk/ok9;->$manager:Llyiahf/vczjk/mk9;

    iget v2, p0, Llyiahf/vczjk/ok9;->$$changed:I

    or-int/lit8 v2, v2, 0x1

    invoke-static {v2}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result v2

    invoke-static {p2, v0, v1, p1, v2}, Llyiahf/vczjk/ok6;->OooOOO0(ZLlyiahf/vczjk/rr7;Llyiahf/vczjk/mk9;Llyiahf/vczjk/rf1;I)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
