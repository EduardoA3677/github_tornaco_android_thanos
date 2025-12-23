.class public abstract Llyiahf/vczjk/kn6;
.super Ljava/lang/Object;
.source "SourceFile"


# instance fields
.field public volatile OooO:I

.field public final OooO00o:Llyiahf/vczjk/or1;

.field public OooO0O0:Llyiahf/vczjk/ni6;

.field public OooO0OO:Llyiahf/vczjk/m7a;

.field public OooO0Oo:Llyiahf/vczjk/vj6;

.field public final OooO0o:Ljava/util/concurrent/CopyOnWriteArrayList;

.field public final OooO0o0:Llyiahf/vczjk/hr5;

.field public final OooO0oO:Llyiahf/vczjk/gq8;

.field public volatile OooO0oo:Z

.field public final OooOO0:Llyiahf/vczjk/s29;

.field public final OooOO0O:Llyiahf/vczjk/gh7;

.field public final OooOO0o:Llyiahf/vczjk/jl8;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/or1;)V
    .locals 3

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/kn6;->OooO00o:Llyiahf/vczjk/or1;

    new-instance p1, Llyiahf/vczjk/gn6;

    invoke-direct {p1}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/kn6;->OooO0OO:Llyiahf/vczjk/m7a;

    sget-object p1, Llyiahf/vczjk/vj6;->OooO0o0:Llyiahf/vczjk/vj6;

    const-string v0, "null cannot be cast to non-null type androidx.paging.PageStore<T of androidx.paging.PageStore.Companion.initial>"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOo(Ljava/lang/Object;Ljava/lang/String;)V

    iput-object p1, p0, Llyiahf/vczjk/kn6;->OooO0Oo:Llyiahf/vczjk/vj6;

    new-instance p1, Llyiahf/vczjk/hr5;

    invoke-direct {p1}, Llyiahf/vczjk/hr5;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/kn6;->OooO0o0:Llyiahf/vczjk/hr5;

    new-instance v0, Ljava/util/concurrent/CopyOnWriteArrayList;

    invoke-direct {v0}, Ljava/util/concurrent/CopyOnWriteArrayList;-><init>()V

    iput-object v0, p0, Llyiahf/vczjk/kn6;->OooO0o:Ljava/util/concurrent/CopyOnWriteArrayList;

    new-instance v1, Llyiahf/vczjk/gq8;

    const/4 v2, 0x1

    invoke-direct {v1, v2}, Llyiahf/vczjk/gq8;-><init>(Z)V

    iput-object v1, p0, Llyiahf/vczjk/kn6;->OooO0oO:Llyiahf/vczjk/gq8;

    sget-object v1, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    invoke-static {v1}, Llyiahf/vczjk/r02;->OooO0Oo(Ljava/lang/Object;)Llyiahf/vczjk/s29;

    move-result-object v1

    iput-object v1, p0, Llyiahf/vczjk/kn6;->OooOO0:Llyiahf/vczjk/s29;

    iget-object p1, p1, Llyiahf/vczjk/hr5;->OooO0OO:Llyiahf/vczjk/gh7;

    iput-object p1, p0, Llyiahf/vczjk/kn6;->OooOO0O:Llyiahf/vczjk/gh7;

    sget-object p1, Llyiahf/vczjk/aj0;->OooOOO:Llyiahf/vczjk/aj0;

    const/4 v1, 0x0

    const/16 v2, 0x40

    invoke-static {v1, v2, p1}, Llyiahf/vczjk/zsa;->OooOO0O(IILlyiahf/vczjk/aj0;)Llyiahf/vczjk/jl8;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/kn6;->OooOO0o:Llyiahf/vczjk/jl8;

    new-instance p1, Llyiahf/vczjk/fn6;

    invoke-direct {p1, p0}, Llyiahf/vczjk/fn6;-><init>(Llyiahf/vczjk/kn6;)V

    invoke-virtual {v0, p1}, Ljava/util/concurrent/CopyOnWriteArrayList;->add(Ljava/lang/Object;)Z

    return-void
.end method

.method public static final OooO00o(Llyiahf/vczjk/kn6;Ljava/util/List;IIZLlyiahf/vczjk/r25;Llyiahf/vczjk/r25;Llyiahf/vczjk/ni6;Llyiahf/vczjk/zo1;)Ljava/lang/Object;
    .locals 5

    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    instance-of v0, p8, Llyiahf/vczjk/jn6;

    if-eqz v0, :cond_0

    move-object v0, p8

    check-cast v0, Llyiahf/vczjk/jn6;

    iget v1, v0, Llyiahf/vczjk/jn6;->label:I

    const/high16 v2, -0x80000000

    and-int v3, v1, v2

    if-eqz v3, :cond_0

    sub-int/2addr v1, v2

    iput v1, v0, Llyiahf/vczjk/jn6;->label:I

    goto :goto_0

    :cond_0
    new-instance v0, Llyiahf/vczjk/jn6;

    invoke-direct {v0, p0, p8}, Llyiahf/vczjk/jn6;-><init>(Llyiahf/vczjk/kn6;Llyiahf/vczjk/zo1;)V

    :goto_0
    iget-object p8, v0, Llyiahf/vczjk/jn6;->result:Ljava/lang/Object;

    sget-object v1, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v2, v0, Llyiahf/vczjk/jn6;->label:I

    const/4 v3, 0x1

    if-eqz v2, :cond_2

    if-ne v2, v3, :cond_1

    iget-boolean p4, v0, Llyiahf/vczjk/jn6;->Z$0:Z

    iget p3, v0, Llyiahf/vczjk/jn6;->I$1:I

    iget p2, v0, Llyiahf/vczjk/jn6;->I$0:I

    iget-object p0, v0, Llyiahf/vczjk/jn6;->L$5:Ljava/lang/Object;

    check-cast p0, Llyiahf/vczjk/vj6;

    iget-object p1, v0, Llyiahf/vczjk/jn6;->L$4:Ljava/lang/Object;

    move-object p7, p1

    check-cast p7, Llyiahf/vczjk/ni6;

    iget-object p1, v0, Llyiahf/vczjk/jn6;->L$3:Ljava/lang/Object;

    move-object p6, p1

    check-cast p6, Llyiahf/vczjk/r25;

    iget-object p1, v0, Llyiahf/vczjk/jn6;->L$2:Ljava/lang/Object;

    move-object p5, p1

    check-cast p5, Llyiahf/vczjk/r25;

    iget-object p1, v0, Llyiahf/vczjk/jn6;->L$1:Ljava/lang/Object;

    check-cast p1, Ljava/util/List;

    iget-object v0, v0, Llyiahf/vczjk/jn6;->L$0:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/kn6;

    invoke-static {p8}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    move-object p8, p0

    move-object p0, v0

    goto :goto_2

    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p0

    :cond_2
    invoke-static {p8}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    if-eqz p4, :cond_4

    if-eqz p5, :cond_3

    goto :goto_1

    :cond_3
    new-instance p0, Ljava/lang/IllegalArgumentException;

    const-string p1, "Cannot dispatch LoadStates in PagingDataPresenter without source LoadStates set."

    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p0

    :cond_4
    :goto_1
    const/4 p8, 0x0

    iput-boolean p8, p0, Llyiahf/vczjk/kn6;->OooO0oo:Z

    new-instance p8, Llyiahf/vczjk/vj6;

    invoke-direct {p8, p1, p2, p3}, Llyiahf/vczjk/vj6;-><init>(Ljava/util/List;II)V

    iget-object v2, p0, Llyiahf/vczjk/kn6;->OooO0Oo:Llyiahf/vczjk/vj6;

    const-string v4, "null cannot be cast to non-null type androidx.paging.PlaceholderPaddedList<T of androidx.paging.PagingDataPresenter>"

    invoke-static {v2, v4}, Llyiahf/vczjk/v34;->OooOo(Ljava/lang/Object;Ljava/lang/String;)V

    iput-object p8, p0, Llyiahf/vczjk/kn6;->OooO0Oo:Llyiahf/vczjk/vj6;

    iput-object p7, p0, Llyiahf/vczjk/kn6;->OooO0O0:Llyiahf/vczjk/ni6;

    new-instance v4, Llyiahf/vczjk/dn6;

    invoke-direct {v4, p8, v2}, Llyiahf/vczjk/dn6;-><init>(Llyiahf/vczjk/vj6;Llyiahf/vczjk/tw6;)V

    iput-object p0, v0, Llyiahf/vczjk/jn6;->L$0:Ljava/lang/Object;

    iput-object p1, v0, Llyiahf/vczjk/jn6;->L$1:Ljava/lang/Object;

    iput-object p5, v0, Llyiahf/vczjk/jn6;->L$2:Ljava/lang/Object;

    iput-object p6, v0, Llyiahf/vczjk/jn6;->L$3:Ljava/lang/Object;

    iput-object p7, v0, Llyiahf/vczjk/jn6;->L$4:Ljava/lang/Object;

    iput-object p8, v0, Llyiahf/vczjk/jn6;->L$5:Ljava/lang/Object;

    iput p2, v0, Llyiahf/vczjk/jn6;->I$0:I

    iput p3, v0, Llyiahf/vczjk/jn6;->I$1:I

    iput-boolean p4, v0, Llyiahf/vczjk/jn6;->Z$0:Z

    iput v3, v0, Llyiahf/vczjk/jn6;->label:I

    invoke-virtual {p0, v4, v0}, Llyiahf/vczjk/kn6;->OooO0OO(Llyiahf/vczjk/en6;Llyiahf/vczjk/zo1;)Ljava/lang/Object;

    move-result-object v0

    if-ne v0, v1, :cond_5

    return-object v1

    :cond_5
    :goto_2
    sget-object v0, Landroid/os/Build;->ID:Ljava/lang/String;

    if-eqz v0, :cond_9

    const-string v0, "Paging"

    const/4 v1, 0x3

    invoke-static {v0, v1}, Landroid/util/Log;->isLoggable(Ljava/lang/String;I)Z

    move-result v1

    if-eqz v1, :cond_9

    new-instance v1, Ljava/lang/StringBuilder;

    const-string v2, "Presenting data (\n                            |   first item: "

    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-static {p1}, Llyiahf/vczjk/d21;->oo000o(Ljava/util/List;)Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/fy9;

    const/4 v3, 0x0

    if-eqz v2, :cond_6

    iget-object v2, v2, Llyiahf/vczjk/fy9;->OooO0O0:Ljava/util/List;

    if-eqz v2, :cond_6

    invoke-static {v2}, Llyiahf/vczjk/d21;->oo000o(Ljava/util/List;)Ljava/lang/Object;

    move-result-object v2

    goto :goto_3

    :cond_6
    move-object v2, v3

    :goto_3
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string v2, "\n                            |   last item: "

    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-static {p1}, Llyiahf/vczjk/d21;->o0OO00O(Ljava/util/List;)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/fy9;

    if-eqz p1, :cond_7

    iget-object p1, p1, Llyiahf/vczjk/fy9;->OooO0O0:Ljava/util/List;

    if-eqz p1, :cond_7

    invoke-static {p1}, Llyiahf/vczjk/d21;->o0OO00O(Ljava/util/List;)Ljava/lang/Object;

    move-result-object p1

    goto :goto_4

    :cond_7
    move-object p1, v3

    :goto_4
    invoke-virtual {v1, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string p1, "\n                            |   placeholdersBefore: "

    invoke-virtual {v1, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v1, p2}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    const-string p1, "\n                            |   placeholdersAfter: "

    invoke-virtual {v1, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v1, p3}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    const-string p1, "\n                            |   hintReceiver: "

    invoke-virtual {v1, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v1, p7}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string p1, "\n                            |   sourceLoadStates: "

    invoke-virtual {v1, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v1, p5}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string p1, "\n                        "

    invoke-virtual {v1, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p1

    if-eqz p6, :cond_8

    new-instance p2, Ljava/lang/StringBuilder;

    invoke-direct {p2}, Ljava/lang/StringBuilder;-><init>()V

    invoke-virtual {p2, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string p1, "|   mediatorLoadStates: "

    invoke-virtual {p2, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {p2, p6}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const/16 p1, 0xa

    invoke-virtual {p2, p1}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    invoke-virtual {p2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p1

    :cond_8
    new-instance p2, Ljava/lang/StringBuilder;

    invoke-direct {p2}, Ljava/lang/StringBuilder;-><init>()V

    invoke-virtual {p2, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string p1, "|)"

    invoke-virtual {p2, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {p2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p1

    invoke-static {p1}, Llyiahf/vczjk/a79;->OooOoO(Ljava/lang/String;)Ljava/lang/String;

    move-result-object p1

    const-string p2, "message"

    invoke-static {p1, p2}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {v0, p1, v3}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    :cond_9
    if-eqz p4, :cond_a

    iget-object p1, p0, Llyiahf/vczjk/kn6;->OooO0o0:Llyiahf/vczjk/hr5;

    invoke-static {p5}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    invoke-virtual {p1, p5, p6}, Llyiahf/vczjk/hr5;->OooO0Oo(Llyiahf/vczjk/r25;Llyiahf/vczjk/r25;)V

    :cond_a
    invoke-virtual {p8}, Llyiahf/vczjk/vj6;->OooO0o0()I

    move-result p1

    if-nez p1, :cond_b

    iget-object p0, p0, Llyiahf/vczjk/kn6;->OooO0O0:Llyiahf/vczjk/ni6;

    if-eqz p0, :cond_b

    iget p1, p8, Llyiahf/vczjk/vj6;->OooO0O0:I

    new-instance p2, Llyiahf/vczjk/nja;

    div-int/lit8 p1, p1, 0x2

    invoke-virtual {p8}, Llyiahf/vczjk/vj6;->OooO0OO()I

    move-result p3

    invoke-virtual {p8}, Llyiahf/vczjk/vj6;->OooO0Oo()I

    move-result p4

    invoke-direct {p2, p1, p1, p3, p4}, Llyiahf/vczjk/oja;-><init>(IIII)V

    invoke-virtual {p0, p2}, Llyiahf/vczjk/ni6;->OooO00o(Llyiahf/vczjk/oja;)V

    :cond_b
    sget-object p0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p0
.end method


# virtual methods
.method public final OooO0O0(I)Ljava/lang/Object;
    .locals 4

    iget-object v0, p0, Llyiahf/vczjk/kn6;->OooOO0:Llyiahf/vczjk/s29;

    :cond_0
    invoke-virtual {v0}, Llyiahf/vczjk/s29;->getValue()Ljava/lang/Object;

    move-result-object v1

    move-object v2, v1

    check-cast v2, Ljava/lang/Boolean;

    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v2, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    invoke-virtual {v0, v1, v2}, Llyiahf/vczjk/s29;->OooOOO(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v1

    if-eqz v1, :cond_0

    const/4 v0, 0x1

    iput-boolean v0, p0, Llyiahf/vczjk/kn6;->OooO0oo:Z

    iput p1, p0, Llyiahf/vczjk/kn6;->OooO:I

    sget-object v1, Landroid/os/Build;->ID:Ljava/lang/String;

    const-string v2, "Paging"

    if-eqz v1, :cond_1

    const/4 v1, 0x2

    invoke-static {v2, v1}, Landroid/util/Log;->isLoggable(Ljava/lang/String;I)Z

    move-result v1

    if-eqz v1, :cond_1

    goto :goto_0

    :cond_1
    const/4 v0, 0x0

    :goto_0
    const/4 v1, 0x0

    if-eqz v0, :cond_2

    new-instance v0, Ljava/lang/StringBuilder;

    const-string v3, "Accessing item index["

    invoke-direct {v0, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    const/16 v3, 0x5d

    invoke-virtual {v0, v3}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    const-string v3, "message"

    invoke-static {v0, v3}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {v2, v0, v1}, Landroid/util/Log;->v(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    :cond_2
    iget-object v0, p0, Llyiahf/vczjk/kn6;->OooO0O0:Llyiahf/vczjk/ni6;

    if-eqz v0, :cond_3

    iget-object v2, p0, Llyiahf/vczjk/kn6;->OooO0Oo:Llyiahf/vczjk/vj6;

    invoke-virtual {v2, p1}, Llyiahf/vczjk/vj6;->OooO00o(I)Llyiahf/vczjk/mja;

    move-result-object v2

    invoke-virtual {v0, v2}, Llyiahf/vczjk/ni6;->OooO00o(Llyiahf/vczjk/oja;)V

    :cond_3
    iget-object v0, p0, Llyiahf/vczjk/kn6;->OooO0Oo:Llyiahf/vczjk/vj6;

    if-ltz p1, :cond_7

    invoke-virtual {v0}, Llyiahf/vczjk/vj6;->OooO0o0()I

    move-result v2

    if-ge p1, v2, :cond_8

    iget v2, v0, Llyiahf/vczjk/vj6;->OooO0OO:I

    sub-int/2addr p1, v2

    if-ltz p1, :cond_5

    iget v2, v0, Llyiahf/vczjk/vj6;->OooO0O0:I

    if-lt p1, v2, :cond_4

    goto :goto_1

    :cond_4
    invoke-virtual {v0, p1}, Llyiahf/vczjk/vj6;->OooO0O0(I)Ljava/lang/Object;

    move-result-object v1

    :cond_5
    :goto_1
    iget-object v2, p0, Llyiahf/vczjk/kn6;->OooOO0:Llyiahf/vczjk/s29;

    :cond_6
    invoke-virtual {v2}, Llyiahf/vczjk/s29;->getValue()Ljava/lang/Object;

    move-result-object p1

    move-object v0, p1

    check-cast v0, Ljava/lang/Boolean;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v0, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    invoke-virtual {v2, p1, v0}, Llyiahf/vczjk/s29;->OooOOO(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result p1

    if-eqz p1, :cond_6

    return-object v1

    :cond_7
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    :cond_8
    new-instance v1, Ljava/lang/IndexOutOfBoundsException;

    const-string v2, "Index: "

    const-string v3, ", Size: "

    invoke-static {p1, v2, v3}, Llyiahf/vczjk/ii5;->OooOOO(ILjava/lang/String;Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object p1

    invoke-virtual {v0}, Llyiahf/vczjk/vj6;->OooO0o0()I

    move-result v0

    invoke-virtual {p1, v0}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p1

    invoke-direct {v1, p1}, Ljava/lang/IndexOutOfBoundsException;-><init>(Ljava/lang/String;)V

    throw v1
.end method

.method public abstract OooO0OO(Llyiahf/vczjk/en6;Llyiahf/vczjk/zo1;)Ljava/lang/Object;
.end method
